//! Wazuh Indexer alert tools
//!
//! This module contains tools for retrieving and analyzing Wazuh security alerts
//! from the Wazuh Indexer.
//!
//! Extended (farmhouse fork) beyond upstream gbrigandi/mcp-server-wazuh to support:
//!   - min_level / start_time / end_time / hours_ago filtering (built server-side,
//!     so the indexer itself narrows results instead of pulling everything and
//!     filtering client-side)
//!   - search_after-based pagination, which is NOT bounded by the indexer's
//!     `index.max_result_window` (10,000 by default) the way `size`/`from` is.
//!     Each response's last content item carries the `next_search_after` cursor
//!     to pass back in on the following call.
//!   - raw:true to get the full `_source` JSON per alert instead of the
//!     flattened 5-field text summary, for fields (OAuth client IDs, message
//!     senders, nested `data.*`) the flattened view doesn't surface.

use rmcp::{
    ErrorData as McpError,
    model::{CallToolResult, Content},
    tool,
};
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use wazuh_client::WazuhIndexerClient;
use super::ToolModule;

/// Parameters for getting alert summary
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetAlertSummaryParams {
    #[schemars(description = "Maximum number of alerts to retrieve in this page (default: 300). A single page is still bounded by the indexer's index.max_result_window (10,000 by default) - use search_after to page past that instead of raising this.")]
    pub limit: Option<u32>,

    #[schemars(description = "Only include alerts with rule.level >= this value, e.g. 12 for high/critical alerts. Filtering is done in the indexer query, not client-side, so it does not cost you result-window slots the way pulling everything and discarding low-level alerts would.")]
    pub min_level: Option<u32>,

    #[schemars(description = "Only include alerts at or after this ISO-8601 timestamp, e.g. \"2026-09-01T00:00:00Z\". Ignored if hours_ago is set.")]
    pub start_time: Option<String>,

    #[schemars(description = "Only include alerts at or before this ISO-8601 timestamp, e.g. \"2026-09-02T00:00:00Z\".")]
    pub end_time: Option<String>,

    #[schemars(description = "Convenience alternative to start_time: only include alerts from the last N hours (e.g. 12 or 24). Takes precedence over start_time if both are given.")]
    pub hours_ago: Option<u32>,

    #[schemars(description = "Pagination cursor. Omit for the first page. To fetch the next page (including pages beyond the indexer's 10,000-result window), pass back the exact 'next_search_after' array printed at the end of the previous call's results.")]
    pub search_after: Option<Vec<Value>>,

    #[schemars(description = "If true, return the full raw alert JSON (_source) for each hit instead of the flattened Alert ID/Time/Agent/Level/Description summary. Use this when you need fields the summary doesn't surface, e.g. OAuth client IDs, message senders/recipients, or other nested data.* fields.")]
    pub raw: Option<bool>,
}

/// Alert tools implementation
#[derive(Clone)]
pub struct AlertTools {
    indexer_client: Arc<WazuhIndexerClient>,
}

impl AlertTools {
    pub fn new(indexer_client: Arc<WazuhIndexerClient>) -> Self {
        Self { indexer_client }
    }

    #[tool(
        name = "get_wazuh_alert_summary",
        description = "Retrieves Wazuh security alerts. Supports server-side filtering by minimum rule level and/or a time range (start_time/end_time or hours_ago), search_after pagination to page past the indexer's 10,000-result window, and an optional raw JSON mode for fields the flattened summary doesn't cover."
    )]
    pub async fn get_wazuh_alert_summary(
        &self,
        params: GetAlertSummaryParams,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(300).min(10_000);
        let raw = params.raw.unwrap_or(false);

        let start_time: Option<String> = if let Some(hours) = params.hours_ago {
            Some(
                (chrono::Utc::now() - chrono::Duration::hours(hours as i64))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
        } else {
            params.start_time.clone()
        };
        let end_time = params.end_time.clone();

        let mut filters: Vec<Value> = Vec::new();
        if let Some(lvl) = params.min_level {
            filters.push(json!({ "range": { "rule.level": { "gte": lvl } } }));
        }
        if start_time.is_some() || end_time.is_some() {
            let mut range = serde_json::Map::new();
            if let Some(ref s) = start_time {
                range.insert("gte".to_string(), json!(s));
            }
            if let Some(ref e) = end_time {
                range.insert("lte".to_string(), json!(e));
            }
            filters.push(json!({ "range": { "timestamp": range } }));
        }

        let query = if filters.is_empty() {
            json!({ "match_all": {} })
        } else {
            json!({ "bool": { "filter": filters } })
        };

        let mut query_body = json!({
            "size": limit,
            "sort": [
                { "timestamp": { "order": "desc" } },
                { "_seq_no": { "order": "desc" } }
            ],
            "query": query
        });

        if let Some(sa) = params.search_after.clone() {
            query_body["search_after"] = json!(sa);
        }

        tracing::info!(
            limit = %limit,
            min_level = ?params.min_level,
            start_time = ?start_time,
            end_time = ?end_time,
            raw = %raw,
            paginated = %params.search_after.is_some(),
            "Retrieving Wazuh alert summary"
        );

        let endpoint = "/wazuh-alerts*/_search";
        match self
            .indexer_client
            .make_indexer_request(Method::POST, endpoint, Some(query_body))
            .await
        {
            Ok(response) => {
                let hits = match response
                    .get("hits")
                    .and_then(|h| h.get("hits"))
                    .and_then(|h_array| h_array.as_array())
                {
                    Some(h) => h.clone(),
                    None => {
                        tracing::error!(?response, "Failed to find 'hits.hits' array in Indexer response");
                        return Self::error_result(
                            "Indexer response missing 'hits.hits' array".to_string(),
                        );
                    }
                };

                if hits.is_empty() {
                    return Self::not_found_result("Wazuh alerts");
                }

                let num_alerts_to_process = hits.len();
                let last_sort = hits.last().and_then(|h| h.get("sort")).cloned();

                let mut mcp_content_items: Vec<Content> = hits
                    .into_iter()
                    .map(|hit| {
                        let source = hit.get("_source").cloned().unwrap_or_else(|| json!({}));
                        let hit_id = hit
                            .get("_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown ID")
                            .to_string();

                        if raw {
                            let pretty = serde_json::to_string_pretty(&source)
                                .unwrap_or_else(|_| source.to_string());
                            Content::text(format!("Alert ID: {}\n{}", hit_id, pretty))
                        } else {
                            Content::text(Self::format_alert_text(&source, &hit_id))
                        }
                    })
                    .collect();

                if let Some(sa) = last_sort {
                    mcp_content_items.push(Content::text(format!(
                        "--- PAGINATION ---\nReturned {} alert(s) this page.\nnext_search_after: {}\nTo continue, call get_wazuh_alert_summary again with the same filters and search_after set to the array above.",
                        num_alerts_to_process, sa
                    )));
                }

                tracing::info!(
                    "Successfully processed {} alerts into {} MCP content items",
                    num_alerts_to_process,
                    mcp_content_items.len()
                );
                Self::success_result(mcp_content_items)
            }
            Err(e) => {
                let err_msg = Self::format_error("Indexer", "retrieving alerts", &e);
                tracing::error!("{}", err_msg);
                Self::error_result(err_msg)
            }
        }
    }

    fn format_alert_text(source: &Value, fallback_id: &str) -> String {
        let id = source
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(fallback_id);

        let description = source
            .get("rule")
            .and_then(|r| r.get("description"))
            .and_then(|d| d.as_str())
            .unwrap_or("No description available");

        let timestamp = source
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("Unknown time");

        let agent_name = source
            .get("agent")
            .and_then(|a| a.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown agent");

        let rule_level = source
            .get("rule")
            .and_then(|r| r.get("level"))
            .and_then(|l| l.as_u64())
            .unwrap_or(0);

        let src_ip = source
            .get("data")
            .and_then(|d| d.get("srcip"))
            .and_then(|ip| ip.as_str())
            .or_else(|| {
                source
                    .get("data")
                    .and_then(|d| d.get("src_ip"))
                    .and_then(|ip| ip.as_str())
            })
            .unwrap_or("");

        let dst_ip = source
            .get("data")
            .and_then(|d| d.get("dstip"))
            .and_then(|ip| ip.as_str())
            .or_else(|| {
                source
                    .get("data")
                    .and_then(|d| d.get("dst_ip"))
                    .and_then(|ip| ip.as_str())
            })
            .unwrap_or("");

        let src_user = source
            .get("data")
            .and_then(|d| d.get("srcuser"))
            .and_then(|u| u.as_str())
            .or_else(|| {
                source
                    .get("data")
                    .and_then(|d| d.get("dstuser"))
                    .and_then(|u| u.as_str())
            })
            .unwrap_or("");

        let mut formatted_text = format!(
            "Alert ID: {}\nTime: {}\nAgent: {}\nLevel: {}\nDescription: {}",
            id, timestamp, agent_name, rule_level, description
        );

        if !src_ip.is_empty() {
            formatted_text.push_str(&format!("\nSource IP: {}", src_ip));
        }
        if !dst_ip.is_empty() {
            formatted_text.push_str(&format!("\nDestination IP: {}", dst_ip));
        }
        if !src_user.is_empty() {
            formatted_text.push_str(&format!("\nUser: {}", src_user));
        }
        formatted_text
    }
}

impl ToolModule for AlertTools {}
