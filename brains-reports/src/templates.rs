//! Report templates and rendering engine

use crate::report_schema::{OutputFormat, ReportTemplate, TemplateType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Template engine for generating formatted reports
pub struct TemplateEngine {
    templates: HashMap<String, ReportTemplate>,
    custom_helpers: HashMap<String, Box<dyn Fn(&Value) -> String>>,
}

/// Template rendering context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderContext {
    pub variables: HashMap<String, Value>,
    pub helpers: HashMap<String, String>,
    pub output_format: OutputFormat,
}

/// Rendered report output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedReport {
    pub report_id: Uuid,
    pub template_name: String,
    pub output_format: OutputFormat,
    pub content: String,
    pub rendered_at: chrono::DateTime<chrono::Utc>,
    pub variables_used: Vec<String>,
    pub file_size: usize,
}

impl TemplateEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
            custom_helpers: HashMap::new(),
        };
        
        engine.register_default_templates();
        
        engine
    }
    
    fn html_escape(&self, input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }
    
    /// Register a template
    pub fn register_template(&mut self, name: String, template: ReportTemplate) {
        self.templates.insert(name, template);
    }
    
    /// Get template by name
    pub fn get_template(&self, name: &str) -> Option<&ReportTemplate> {
        self.templates.get(name)
    }
    
    /// Render template with context
    pub fn render(
        &self,
        template_name: &str,
        context: &RenderContext,
    ) -> anyhow::Result<RenderedReport> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| anyhow::anyhow!("Template not found: {}", template_name))?;
        
        let content = self.render_template_content(&template.content, context)?;
        
        let variables_used = context.variables.keys().cloned().collect();
        
        Ok(RenderedReport {
            report_id: Uuid::new_v4(),
            template_name: template_name.to_string(),
            output_format: context.output_format.clone(),
            content: content.clone(),
            rendered_at: chrono::Utc::now(),
            variables_used,
            file_size: content.len(),
        })
    }
    
    /// Render template content with variable substitution
    fn render_template_content(
        &self,
        template_content: &str,
        context: &RenderContext,
    ) -> anyhow::Result<String> {
        let mut rendered = template_content.to_string();
        
        for (key, value) in &context.variables {
            let placeholder = format!("{{{{{}}}}}", key);
            let replacement = match context.output_format {
                OutputFormat::Html => self.html_escape(&self.value_to_string(value)),
                _ => self.value_to_string(value),
            };
            rendered = rendered.replace(&placeholder, &replacement);
        }
        
        match context.output_format {
            OutputFormat::Html => self.process_html(&rendered),
            OutputFormat::Markdown => Ok(rendered),
            OutputFormat::Json => self.process_json(&rendered),
            OutputFormat::Yaml => self.process_yaml(&rendered),
            _ => Ok(rendered),
        }
    }
    
    /// Convert JSON value to string
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| self.value_to_string(v)).collect();
                format!("[{}]", items.join(", "))
            }
            Value::Object(obj) => {
                let pairs: Vec<String> = obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, self.value_to_string(v)))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
            Value::Null => "null".to_string(),
        }
    }
    
    /// Process HTML output
    fn process_html(&self, content: &str) -> anyhow::Result<String> {
        // Add HTML wrapper
        let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .evidence {{ background-color: #f8f9fa; padding: 10px; margin: 10px 0; }}
        .signature {{ margin-top: 30px; padding: 20px; background-color: #e9ecef; }}
    </style>
</head>
<body>
{}
</body>
</html>"#, content);
        
        Ok(html)
    }
    
    /// Process JSON output
    fn process_json(&self, content: &str) -> anyhow::Result<String> {
        // Validate JSON structure
        let _: Value = serde_json::from_str(content)?;
        Ok(content.to_string())
    }
    
    /// Process YAML output
    fn process_yaml(&self, content: &str) -> anyhow::Result<String> {
        // Validate YAML structure
        let _: Value = serde_yaml::from_str(content)?;
        Ok(content.to_string())
    }
    
    /// Register default templates
    fn register_default_templates(&mut self) {
        // Executive Summary Template
        let executive_template = ReportTemplate {
            template_id: Uuid::new_v4(),
            template_name: "Executive Summary".to_string(),
            description: "High-level executive summary for stakeholders".to_string(),
            template_type: TemplateType::Executive,
            content: self.executive_summary_template(),
            variables: vec![],
            output_format: OutputFormat::Html,
        };
        
        self.templates.insert("executive".to_string(), executive_template);
        
        // Technical Report Template
        let technical_template = ReportTemplate {
            template_id: Uuid::new_v4(),
            template_name: "Technical Analysis".to_string(),
            description: "Detailed technical analysis report".to_string(),
            template_type: TemplateType::Technical,
            content: self.technical_report_template(),
            variables: vec![],
            output_format: OutputFormat::Html,
        };
        
        self.templates.insert("technical".to_string(), technical_template);
        
        // Legal Report Template
        let legal_template = ReportTemplate {
            template_id: Uuid::new_v4(),
            template_name: "Legal Analysis".to_string(),
            description: "Legal-focused analysis report".to_string(),
            template_type: TemplateType::Legal,
            content: self.legal_report_template(),
            variables: vec![],
            output_format: OutputFormat::Html,
        };
        
        self.templates.insert("legal".to_string(), legal_template);
    }
    
    /// Executive summary template
    fn executive_summary_template(&self) -> String {
        r#"<div class="header">
    <h1>{{report_title}}</h1>
    <p><strong>Report ID:</strong> {{report_id}}</p>
    <p><strong>Date:</strong> {{created_at}}</p>
    <p><strong>Investigator:</strong> {{investigator_name}}</p>
</div>

<h2>Executive Summary</h2>
<p>{{summary}}</p>

<h2>Key Findings</h2>
<div class="finding critical">
    <h3>Critical Findings: {{critical_findings_count}}</h3>
    <p>{{critical_findings_summary}}</p>
</div>

<div class="finding high">
    <h3>High Priority Findings: {{high_findings_count}}</h3>
    <p>{{high_findings_summary}}</p>
</div>

<h2>Recommendations</h2>
<ul>
{{recommendations_list}}
</ul>

<h2>Conclusion</h2>
<p>{{conclusion}}</p>

<div class="signature">
    <p><strong>Signed:</strong> {{investigator_name}}</p>
    <p><strong>Date:</strong> {{signed_at}}</p>
    <p><strong>Signature:</strong> {{signature}}</p>
</div>"#.to_string()
    }
    
    /// Technical report template
    fn technical_report_template(&self) -> String {
        r#"<div class="header">
    <h1>{{report_title}}</h1>
    <p><strong>Report ID:</strong> {{report_id}}</p>
    <p><strong>Date:</strong> {{created_at}}</p>
    <p><strong>Investigator:</strong> {{investigator_name}}</p>
</div>

<h2>Technical Analysis Summary</h2>
<p>{{summary}}</p>

<h2>Methodology</h2>
<p><strong>Approach:</strong> {{methodology_approach}}</p>
<p><strong>Tools Used:</strong> {{tools_used}}</p>
<p><strong>Standards:</strong> {{standards_followed}}</p>

<h2>Detailed Findings</h2>
{{findings_detailed}}

<h2>Evidence Analysis</h2>
{{evidence_analysis}}

<h2>Technical Recommendations</h2>
<ul>
{{technical_recommendations}}
</ul>

<h2>Appendices</h2>
{{appendices}}

<div class="signature">
    <p><strong>Technical Lead:</strong> {{investigator_name}}</p>
    <p><strong>Date:</strong> {{signed_at}}</p>
    <p><strong>Digital Signature:</strong> {{signature}}</p>
</div>"#.to_string()
    }
    
    /// Legal report template
    fn legal_report_template(&self) -> String {
        r#"<div class="header">
    <h1>{{report_title}}</h1>
    <p><strong>Report ID:</strong> {{report_id}}</p>
    <p><strong>Case ID:</strong> {{case_id}}</p>
    <p><strong>Date:</strong> {{created_at}}</p>
    <p><strong>Investigator:</strong> {{investigator_name}}</p>
</div>

<h2>Legal Summary</h2>
<p>{{summary}}</p>

<h2>Chain of Custody</h2>
<p><strong>Evidence ID:</strong> {{evidence_id}}</p>
<p><strong>Collection Date:</strong> {{collection_date}}</p>
<p><strong>Custodian:</strong> {{current_custodian}}</p>

<h2>Findings with Legal Implications</h2>
{{legal_findings}}

<h2>Compliance Assessment</h2>
<p>{{compliance_assessment}}</p>

<h2>Legal Recommendations</h2>
<ul>
{{legal_recommendations}}
</ul>

<h2>Certification</h2>
<p>I hereby certify that this analysis was conducted in accordance with accepted forensic practices and that the findings are accurate to the best of my knowledge.</p>

<div class="signature">
    <p><strong>Forensic Analyst:</strong> {{investigator_name}}</p>
    <p><strong>Credentials:</strong> {{credentials}}</p>
    <p><strong>Date:</strong> {{signed_at}}</p>
    <p><strong>Digital Signature:</strong> {{signature}}</p>
</div>"#.to_string()
    }
    
    /// List available templates
    pub fn list_templates(&self) -> Vec<&ReportTemplate> {
        self.templates.values().collect()
    }
    
    /// Get template by type
    pub fn get_templates_by_type(&self, template_type: TemplateType) -> Vec<&ReportTemplate> {
        self.templates
            .values()
            .filter(|t| t.template_type == template_type)
            .collect()
    }
}

impl std::fmt::Debug for TemplateEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateEngine")
            .field("templates", &self.templates.keys().collect::<Vec<_>>())
            .field("custom_helpers", &format!("{} helpers", self.custom_helpers.len()))
            .finish()
    }
}

impl Clone for TemplateEngine {
    fn clone(&self) -> Self {
        let mut engine = Self {
            templates: self.templates.clone(),
            custom_helpers: HashMap::new(), // Cannot clone function objects
        };
        
        // Re-register default templates
        engine.register_default_templates();
        
        engine
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_template_engine_creation() {
        let engine = TemplateEngine::new();
        assert!(!engine.templates.is_empty());
        assert!(engine.get_template("executive").is_some());
    }
    
    #[test]
    fn test_template_rendering() {
        let engine = TemplateEngine::new();
        
        let mut context = RenderContext {
            variables: HashMap::new(),
            helpers: HashMap::new(),
            output_format: OutputFormat::Html,
        };
        
        context.variables.insert("report_title".to_string(), json!("Test Report"));
        context.variables.insert("report_id".to_string(), json!("RPT-001"));
        context.variables.insert("investigator_name".to_string(), json!("John Doe"));
        
        let result = engine.render("executive", &context);
        assert!(result.is_ok());
        
        let rendered = result.unwrap();
        assert!(rendered.content.contains("Test Report"));
        assert!(rendered.content.contains("RPT-001"));
        assert!(rendered.content.contains("John Doe"));
    }
    
    #[test]
    fn test_template_listing() {
        let engine = TemplateEngine::new();
        let templates = engine.list_templates();
        assert!(!templates.is_empty());
        
        let executive_templates = engine.get_templates_by_type(TemplateType::Executive);
        assert!(!executive_templates.is_empty());
    }
    
    #[test]
    fn test_html_escaping() {
        let engine = TemplateEngine::new();
        
        let mut context = RenderContext {
            variables: HashMap::new(),
            helpers: HashMap::new(),
            output_format: OutputFormat::Html,
        };
        
        context.variables.insert("malicious_title".to_string(), 
            Value::String("<script>alert('xss')</script>".to_string()));
        
        let result = engine.render("executive", &context);
        assert!(result.is_ok());
        
        let rendered = result.unwrap();
        assert!(rendered.content.contains("&lt;script&gt;"));
        assert!(rendered.content.contains("&lt;/script&gt;"));
        assert!(!rendered.content.contains("<script>"));
    }
}
