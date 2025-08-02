use tree_sitter::{Parser, TreeCursor};

use crate::PatternMatch;

pub trait ASTPatternAnalyzerTrait {
    fn language(&self) -> &'static str;
    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch>;
}

pub struct ASTPatternAnalyzer {
    rust_analyzer: RustPatternAnalyzer,
    javascript_analyzer: JavascriptPatternAnalyzer,
    python_analyzer: PythonPatternAnalyzer,
}

impl ASTPatternAnalyzer {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            rust_analyzer: RustPatternAnalyzer::new()?,
            javascript_analyzer: JavascriptPatternAnalyzer::new()?,
            python_analyzer: PythonPatternAnalyzer::new()?,
        })
    }

    pub fn analyze_code(&mut self, source_code: &str, language: &str) -> Vec<PatternMatch> {
        match language.to_lowercase().as_str() {
            "rust" => self.rust_analyzer.analyze_code(source_code),
            "javascript" | "js" => self.javascript_analyzer.analyze_code(source_code),
            "python" | "py" => self.python_analyzer.analyze_code(source_code),
            _ => vec![],
        }
    }
}

pub struct RustPatternAnalyzer {
    parser: Parser,
}

impl RustPatternAnalyzer {
    pub fn new() -> anyhow::Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_rust::language()).map_err(|e| anyhow::anyhow!("Error loading Rust grammar: {}", e))?;
        Ok(Self { parser })
    }

    #[allow(clippy::only_used_in_recursion)]
    fn detect_suspicious_vars(&self, cursor: &mut TreeCursor, source: &str, results: &mut Vec<PatternMatch>) {
        loop {
            let node = cursor.node();

            if node.kind() == "identifier" {
                let var_name = node.utf8_text(source.as_bytes()).unwrap_or_default();

                // Basic heuristic: generic or suspicious variable names often used in LLM-generated code
                let suspicious_names = ["data", "result", "output", "temp", "var"];
                if suspicious_names.contains(&var_name) {
                    let start = node.start_byte();
                    let end = node.end_byte();

                    results.push(PatternMatch {
                        pattern_name: "SuspiciousVariableName".to_string(),
                        confidence: 0.6,
                        evidence: format!("Identifier: {var_name}"),
                        line_range: (node.start_position().row, node.end_position().row),
                        node_range: (start, end),
                        context: format!("Variable name '{var_name}' is commonly used in LLM-generated code"),
                        metadata: serde_json::json!({
                            "variable_name": var_name,
                            "pattern_type": "generic_identifier"
                        }),
                    });
                }
            }

            if cursor.goto_first_child() {
                self.detect_suspicious_vars(cursor, source, results);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn detect_llm_patterns(&self, cursor: &mut TreeCursor, source: &str, results: &mut Vec<PatternMatch>) {
        loop {
            let node = cursor.node();

            // Detect verbose function signatures (common in LLM code)
            if node.kind() == "function_item" {
                let func_text = node.utf8_text(source.as_bytes()).unwrap_or_default();
                
                // Check for overly verbose parameter names
                if func_text.contains("parameter") || func_text.contains("argument") {
                    let start = node.start_byte();
                    let end = node.end_byte();

                    results.push(PatternMatch {
                        pattern_name: "VerboseFunctionSignature".to_string(),
                        confidence: 0.7,
                        evidence: "Function with verbose parameter names".to_string(),
                        line_range: (node.start_position().row, node.end_position().row),
                        node_range: (start, end),
                        context: "Function signature uses verbose parameter naming typical of LLM-generated code".to_string(),
                        metadata: serde_json::json!({
                            "pattern_type": "verbose_signature"
                        }),
                    });
                }
            }

            // Detect excessive comments (another LLM pattern)
            if node.kind() == "line_comment" || node.kind() == "block_comment" {
                let comment_text = node.utf8_text(source.as_bytes()).unwrap_or_default();
                
                if comment_text.len() > 100 {
                    let start = node.start_byte();
                    let end = node.end_byte();

                    results.push(PatternMatch {
                        pattern_name: "ExcessiveComments".to_string(),
                        confidence: 0.5,
                        evidence: format!("Long comment: {} chars", comment_text.len()),
                        line_range: (node.start_position().row, node.end_position().row),
                        node_range: (start, end),
                        context: "Unusually long comment typical of LLM-generated explanatory code".to_string(),
                        metadata: serde_json::json!({
                            "comment_length": comment_text.len(),
                            "pattern_type": "excessive_documentation"
                        }),
                    });
                }
            }

            if cursor.goto_first_child() {
                self.detect_llm_patterns(cursor, source, results);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

impl ASTPatternAnalyzerTrait for RustPatternAnalyzer {
    fn language(&self) -> &'static str {
        "rust"
    }

    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch> {
        let tree = match self.parser.parse(source_code, None) {
            Some(tree) => tree,
            None => return vec![],
        };

        let mut cursor = tree.root_node().walk();
        let mut results = Vec::new();

        self.detect_suspicious_vars(&mut cursor, source_code, &mut results);
        
        // Reset cursor for next analysis
        cursor = tree.root_node().walk();
        self.detect_llm_patterns(&mut cursor, source_code, &mut results);

        results
    }
}

pub struct JavascriptPatternAnalyzer {
    parser: Parser,
}

impl JavascriptPatternAnalyzer {
    pub fn new() -> anyhow::Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_javascript::language()).map_err(|e| anyhow::anyhow!("Error loading JavaScript grammar: {}", e))?;
        Ok(Self { parser })
    }
}

impl ASTPatternAnalyzerTrait for JavascriptPatternAnalyzer {
    fn language(&self) -> &'static str {
        "javascript"
    }

    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch> {
        let _tree = match self.parser.parse(source_code, None) {
            Some(tree) => tree,
            None => return vec![],
        };

        // Add JS-specific pattern detection here
        vec![]
    }
}

pub struct PythonPatternAnalyzer {
    parser: Parser,
}

impl PythonPatternAnalyzer {
    pub fn new() -> anyhow::Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_python::language()).map_err(|e| anyhow::anyhow!("Error loading Python grammar: {}", e))?;
        Ok(Self { parser })
    }
}

impl ASTPatternAnalyzerTrait for PythonPatternAnalyzer {
    fn language(&self) -> &'static str {
        "python"
    }

    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch> {
        let _tree = match self.parser.parse(source_code, None) {
            Some(tree) => tree,
            None => return vec![],
        };

        // Add Python-specific pattern detection here
        vec![]
    }
}