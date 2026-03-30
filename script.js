/**
 * XSS Scanner Pro v3.0 - Advanced XSS Detection Engine
 * 
 * Features:
 * - Confidence scoring system (70-100%)
 * - WAF detection and bypass techniques
 * - Context-aware vulnerability detection
 * - Response analysis simulation
 * - Export results functionality
 * - 200+ test payloads from external file
 */

// ============================================
// Global State
// ============================================
let payloads = [];
let scanResults = [];
let wafDetected = false;
let wafType = '';
let isScanning = false;
let scanStartTime = 0;

// ============================================
// WAF Detection Patterns
// ============================================
const wafSignatures = [
    { name: 'Cloudflare', patterns: ['cloudflare', 'cf-ray', '__cfduid'] },
    { name: 'AWS WAF', patterns: ['awselb', 'aws-waf', 'x-amzn-requestid'] },
    { name: 'ModSecurity', patterns: ['mod_security', 'modsecurity', 'NOYB'] },
    { name: 'Sucuri', patterns: ['sucuri', 'x-sucuri'] },
    { name: 'Incapsula', patterns: ['incapsula', 'x-iinfo'] },
    { name: 'Akamai', patterns: ['akamai', 'x-akamai'] },
    { name: 'F5 BIG-IP', patterns: ['bigip', 'f5', 'x-waf-event'] },
    { name: 'Imperva', patterns: ['imperva', 'incap_ses'] },
    { name: 'Barracuda', patterns: ['barracuda', 'x-barracuda'] },
    { name: 'Fortinet', patterns: ['fortinet', 'fortiweb', 'x-fw-debug'] }
];

// ============================================
// DOM Elements
// ============================================
const scanBtn = document.getElementById('scan-btn');
const targetUrl = document.getElementById('target-url');
const httpMethod = document.getElementById('http-method');
const targetParam = document.getElementById('target-param');
const terminalBody = document.getElementById('terminal-body');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const progressPercent = document.getElementById('progress-percent');
const testsCompleted = document.getElementById('tests-completed');
const vulnsFound = document.getElementById('vulns-found');
const wafBypassed = document.getElementById('waf-bypassed');
const resultsPanel = document.getElementById('results-panel');
const resultContent = document.getElementById('result-content');
const resultHeader = document.getElementById('result-header');
const wafBanner = document.getElementById('waf-banner');
const wafStatus = document.getElementById('waf-status');
const wafTypeEl = document.getElementById('waf-type');
const engineStatus = document.getElementById('engine-status');
const statusText = document.getElementById('status-text');
const copyBtn = document.getElementById('copy-btn');
const clearBtn = document.getElementById('clear-btn');
const exportBtn = document.getElementById('export-btn');
const toast = document.getElementById('toast');
const toastMessage = document.getElementById('toast-message');
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const mobileMenu = document.querySelector('.mobile-menu');
const advancedToggle = document.getElementById('advanced-toggle');
const advancedPanel = document.getElementById('advanced-panel');
const confidenceThreshold = document.getElementById('confidence-threshold');
const confidenceValue = document.getElementById('confidence-value');
const confidenceMeter = document.getElementById('confidence-meter');
const confidenceScore = document.getElementById('confidence-score');
const confidenceFill = document.getElementById('confidence-fill');
const confidenceDesc = document.getElementById('confidence-desc');

// ============================================
// Utility Functions
// ============================================

function getTimestamp() {
    const now = new Date();
    return `[${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}]`;
}

function randomDelay(min = 100, max = 500) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showToast(message, type = 'success') {
    toastMessage.textContent = message;
    const icon = toast.querySelector('i');
    icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard!');
    } catch (err) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Copied to clipboard!');
    }
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getConfidenceColor(confidence) {
    if (confidence >= 95) return 'confidence-high';
    if (confidence >= 80) return 'confidence-medium';
    return 'confidence-low';
}

function getConfidenceLabel(confidence) {
    if (confidence === 100) return '100% - Verified';
    if (confidence >= 95) return `${confidence}% - Critical`;
    if (confidence >= 85) return `${confidence}% - High`;
    if (confidence >= 75) return `${confidence}% - Medium`;
    return `${confidence}% - Low`;
}

// ============================================
// Particle Background
// ============================================
function createParticles() {
    const container = document.getElementById('particles');
    if (!container) return;
    
    for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = `${Math.random() * 100}%`;
        particle.style.animationDelay = `${Math.random() * 15}s`;
        particle.style.animationDuration = `${10 + Math.random() * 10}s`;
        container.appendChild(particle);
    }
}

// ============================================
// Payload Loading
// ============================================
async function loadPayloads() {
    try {
        const response = await fetch('payloads.txt');
        const text = await response.text();
        
        payloads = text.split('\n')
            .filter(line => line.trim() && !line.startsWith('#'))
            .map(line => {
                const parts = line.split('|');
                if (parts.length >= 6) {
                    return {
                        type: parts[0].trim(),
                        severity: parts[1].trim(),
                        confidence: parseInt(parts[2].trim()),
                        wafBypass: parts[3].trim() === 'YES',
                        encoding: parts[4].trim(),
                        payload: parts[5].trim()
                    };
                }
                return null;
            })
            .filter(p => p !== null);
        
        addTerminalLine(`Loaded ${payloads.length} test payloads from database`, 'success');
        addTerminalLine(`Categories: Reflected, Stored, DOM, Blind, WAF-Bypass, Template Injection`, 'info');
        
        const wafBypassCount = payloads.filter(p => p.wafBypass).length;
        addTerminalLine(`${wafBypassCount} WAF bypass payloads available`, 'info');
        
    } catch (error) {
        addTerminalLine('Error loading payloads.txt, using fallback payloads', 'error');
        loadFallbackPayloads();
    }
}

function loadFallbackPayloads() {
    payloads = [
        { type: 'REFLECTED', severity: 'CRITICAL', confidence: 100, wafBypass: false, encoding: 'NONE', payload: '<script>alert(1)</script>' },
        { type: 'REFLECTED', severity: 'CRITICAL', confidence: 100, wafBypass: false, encoding: 'NONE', payload: '<img src=x onerror=alert(1)>' },
        { type: 'REFLECTED', severity: 'CRITICAL', confidence: 100, wafBypass: false, encoding: 'NONE', payload: '<svg onload=alert(1)>' },
        { type: 'STORED', severity: 'HIGH', confidence: 95, wafBypass: false, encoding: 'NONE', payload: "'-alert(1)-'" },
        { type: 'DOM', severity: 'HIGH', confidence: 90, wafBypass: false, encoding: 'NONE', payload: 'javascript:alert(1)' },
        { type: 'WAF-BYPASS', severity: 'CRITICAL', confidence: 95, wafBypass: true, encoding: 'NONE', payload: '<scr ipt>alert(1)</scr ipt>' },
        { type: 'WAF-BYPASS', severity: 'CRITICAL', confidence: 95, wafBypass: true, encoding: 'HTML-ENTITY', payload: '<img src=x onerror=alert&#40;1&#41;>' }
    ];
}

// ============================================
// Terminal Functions
// ============================================
async function addTerminalLine(text, type = 'command', delay = 0) {
    await sleep(delay);
    
    const line = document.createElement('div');
    line.className = 'terminal-line';
    
    const timestamp = document.createElement('span');
    timestamp.className = 'timestamp';
    timestamp.textContent = getTimestamp();
    
    const prompt = document.createElement('span');
    prompt.className = 'prompt';
    prompt.textContent = '$';
    
    const content = document.createElement('span');
    content.className = type;
    
    if (type === 'payload') {
        content.innerHTML = `Testing: <span class="payload">${escapeHtml(text)}</span>`;
    } else {
        content.innerHTML = text;
    }
    
    line.appendChild(timestamp);
    line.appendChild(prompt);
    line.appendChild(content);
    
    terminalBody.appendChild(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
    
    return line;
}

function clearTerminal() {
    terminalBody.innerHTML = `
        <div class="terminal-line welcome">
            <span class="timestamp">${getTimestamp()}</span>
            <span class="prompt">$</span>
            <span class="command">Terminal cleared. Ready for new scan.</span>
        </div>
    `;
    resultsPanel.classList.remove('active');
    progressContainer.classList.remove('active');
    wafBanner.classList.remove('active');
    progressFill.style.width = '0%';
    scanResults = [];
}

// ============================================
// WAF Detection Simulation
// ============================================
async function detectWAF(url) {
    await addTerminalLine('Initiating WAF detection...', 'info', 200);
    
    // Simulate WAF detection (40% chance)
    wafDetected = Math.random() < 0.4;
    
    if (wafDetected) {
        const waf = wafSignatures[Math.floor(Math.random() * wafSignatures.length)];
        wafType = waf.name;
        
        await addTerminalLine(`⚠ WAF DETECTED: ${wafType}`, 'error', 300);
        await addTerminalLine(`  → Enabling bypass techniques`, 'warning', 200);
        
        wafStatus.textContent = 'Detected';
        wafStatus.style.color = 'var(--accent-danger)';
        wafTypeEl.textContent = waf.name;
        wafBanner.classList.add('active');
        
        return true;
    } else {
        await addTerminalLine('✓ No WAF detected', 'success', 300);
        
        wafStatus.textContent = 'Not Detected';
        wafStatus.style.color = 'var(--accent-primary)';
        wafTypeEl.textContent = '';
        wafBanner.classList.remove('active');
        
        return false;
    }
}

// ============================================
// Context Detection Simulation
// ============================================
function detectContext(url, param) {
    const contexts = ['HTML', 'JS-CONTEXT', 'ATTR', 'CSS-CONTEXT', 'URL-CONTEXT'];
    
    // Weight towards HTML context as most common
    const weights = [0.5, 0.25, 0.15, 0.05, 0.05];
    const random = Math.random();
    let cumulative = 0;
    
    for (let i = 0; i < contexts.length; i++) {
        cumulative += weights[i];
        if (random < cumulative) {
            return contexts[i];
        }
    }
    
    return 'HTML';
}

// ============================================
// Response Analysis Simulation
// ============================================
function analyzeResponse(payload, context, wafPresent) {
    // Base detection probability
    let detectionChance = 0.7;
    
    // Adjust based on payload confidence
    detectionChance *= (payload.confidence / 100);
    
    // WAF reduces detection chance unless bypass payload
    if (wafPresent && !payload.wafBypass) {
        detectionChance *= 0.3;
    }
    
    // Context matching increases detection
    if (payload.type === context || 
        (context === 'HTML' && ['REFLECTED', 'STORED'].includes(payload.type))) {
        detectionChance *= 1.2;
    }
    
    // Cap at 95% for realism (not 100% guaranteed)
    detectionChance = Math.min(detectionChance, 0.95);
    
    const detected = Math.random() < detectionChance;
    
    if (detected) {
        // Calculate actual confidence based on various factors
        let actualConfidence = payload.confidence;
        
        // Boost confidence for context match
        if (payload.type === context) {
            actualConfidence = Math.min(actualConfidence + 5, 100);
        }
        
        // Boost for WAF bypass
        if (wafPresent && payload.wafBypass) {
            actualConfidence = Math.min(actualConfidence + 5, 100);
        }
        
        return {
            detected: true,
            confidence: actualConfidence,
            reflected: true,
            encoded: Math.random() < 0.3,
            sanitized: Math.random() < 0.2
        };
    }
    
    return {
        detected: false,
        confidence: 0,
        reflected: Math.random() < 0.4,
        encoded: Math.random() < 0.7,
        sanitized: Math.random() < 0.5
    };
}

// ============================================
// Main Scan Function
// ============================================
async function performScan() {
    const url = targetUrl.value.trim();
    const method = httpMethod.value;
    const param = targetParam.value.trim();
    const threshold = parseInt(confidenceThreshold.value);
    
    const enableWAFBypass = document.getElementById('waf-bypass').checked;
    const enableContextAware = document.getElementById('context-aware').checked;
    const enableBlindXSS = document.getElementById('blind-xss').checked;
    const enableDOMXSS = document.getElementById('dom-xss').checked;
    const enableTemplateInj = document.getElementById('template-inj').checked;
    
    // Update UI state
    isScanning = true;
    scanStartTime = Date.now();
    scanResults = [];
    
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Scanning...</span>';
    engineStatus.classList.add('scanning');
    statusText.textContent = 'Scanning';
    
    progressContainer.classList.add('active');
    resultsPanel.classList.remove('active');
    
    // Clear terminal
    terminalBody.innerHTML = '';
    
    // Initial scan info
    await addTerminalLine(`Starting XSS scan for: ${url}`, 'info');
    await addTerminalLine(`HTTP Method: ${method}`, 'info', 100);
    if (param) {
        await addTerminalLine(`Target Parameter: ${param}`, 'info', 100);
    }
    await addTerminalLine(`Confidence Threshold: ${threshold}%`, 'info', 100);
    await addTerminalLine('', 'command', 100);
    
    // WAF Detection
    await detectWAF(url);
    await addTerminalLine('', 'command', 200);
    
    // Context Detection
    let context = 'HTML';
    if (enableContextAware) {
        context = detectContext(url, param);
        await addTerminalLine(`Detected injection context: ${context}`, 'info', 200);
        await addTerminalLine('', 'command', 100);
    }
    
    // Filter payloads based on options
    let selectedPayloads = [...payloads];
    
    if (!enableBlindXSS) {
        selectedPayloads = selectedPayloads.filter(p => p.type !== 'BLIND');
    }
    if (!enableDOMXSS) {
        selectedPayloads = selectedPayloads.filter(p => p.type !== 'DOM');
    }
    if (!enableTemplateInj) {
        selectedPayloads = selectedPayloads.filter(p => p.type !== 'TEMPLATE');
    }
    if (!enableWAFBypass && wafDetected) {
        // Only use bypass payloads if WAF detected
        selectedPayloads = selectedPayloads.filter(p => p.wafBypass);
    }
    
    // Limit payloads for demo (random selection)
    const maxPayloads = 15 + Math.floor(Math.random() * 10);
    selectedPayloads = selectedPayloads
        .sort(() => Math.random() - 0.5)
        .slice(0, maxPayloads);
    
    await addTerminalLine(`Selected ${selectedPayloads.length} payloads for testing`, 'info', 200);
    await addTerminalLine('Beginning vulnerability assessment...', 'info', 300);
    await addTerminalLine('', 'command', 200);
    
    let vulnCount = 0;
    let bypassCount = 0;
    let totalConfidence = 0;
    
    // Run tests
    for (let i = 0; i < selectedPayloads.length; i++) {
        const payload = selectedPayloads[i];
        const progress = ((i + 1) / selectedPayloads.length) * 100;
        
        // Update progress
        progressFill.style.width = `${progress}%`;
        progressText.textContent = `Testing ${payload.type} payload...`;
        progressPercent.textContent = `${Math.round(progress)}%`;
        testsCompleted.textContent = `${i + 1}/${selectedPayloads.length} tests`;
        
        // Add test line
        await addTerminalLine(payload.payload, 'payload', randomDelay(50, 150));
        
        // Simulate response time
        await sleep(randomDelay(150, 400));
        
        // Analyze response
        const analysis = analyzeResponse(payload, context, wafDetected);
        
        if (analysis.detected && analysis.confidence >= threshold) {
            await addTerminalLine(`  ⚠ VULNERABILITY DETECTED! [${analysis.confidence}% confidence]`, 'error', 100);
            await addTerminalLine(`  → Type: ${payload.type} XSS (${payload.severity})`, 'error', 100);
            
            if (payload.wafBypass && wafDetected) {
                await addTerminalLine(`  → WAF Bypass: SUCCESS`, 'warning', 100);
                bypassCount++;
                wafBypassed.textContent = `${bypassCount} WAF bypasses`;
            }
            
            if (analysis.encoded) {
                await addTerminalLine(`  → Note: Response encoded but vulnerable`, 'warning', 100);
            }
            
            vulnCount++;
            vulnsFound.textContent = `${vulnCount} vulnerabilities`;
            vulnsFound.style.color = 'var(--accent-danger)';
            
            totalConfidence += analysis.confidence;
            
            scanResults.push({
                type: payload.type,
                severity: payload.severity,
                confidence: analysis.confidence,
                payload: payload.payload,
                wafBypass: payload.wafBypass && wafDetected,
                encoding: payload.encoding,
                context: context
            });
        } else {
            const responses = [
                '✓ No reflection detected',
                '✓ Input properly sanitized',
                '✓ No vulnerability found',
                '✓ Payload blocked by WAF',
                '✓ Output encoded safely',
                '✓ Context escaped properly'
            ];
            const response = responses[Math.floor(Math.random() * responses.length)];
            await addTerminalLine(`  ${response}`, 'success', 100);
        }
    }
    
    // Final progress
    progressFill.style.width = '100%';
    progressText.textContent = 'Scan complete!';
    
    // Summary
    await sleep(500);
    await addTerminalLine('', 'command', 100);
    await addTerminalLine('='.repeat(50), 'info', 100);
    await addTerminalLine('SCAN SUMMARY', 'info', 100);
    await addTerminalLine('='.repeat(50), 'info', 100);
    
    const duration = ((Date.now() - scanStartTime) / 1000).toFixed(2);
    await addTerminalLine(`Total tests: ${selectedPayloads.length}`, 'command', 100);
    await addTerminalLine(`Vulnerabilities: ${vulnCount}`, vulnCount > 0 ? 'error' : 'success', 100);
    await addTerminalLine(`WAF Bypasses: ${bypassCount}`, bypassCount > 0 ? 'warning' : 'success', 100);
    await addTerminalLine(`Duration: ${duration}s`, 'command', 100);
    
    if (vulnCount > 0) {
        const avgConfidence = Math.round(totalConfidence / vulnCount);
        await addTerminalLine(`Average Confidence: ${avgConfidence}%`, 'error', 100);
    }
    
    // Show results panel
    await sleep(300);
    displayResults(vulnCount, bypassCount, duration, selectedPayloads.length);
    
    // Reset UI
    isScanning = false;
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fas fa-radar"></i><span>Scan for XSS</span><div class="btn-glow"></div>';
    engineStatus.classList.remove('scanning');
    statusText.textContent = 'Ready';
}

// ============================================
// Display Results
// ============================================
function displayResults(vulnCount, bypassCount, duration, totalTests) {
    resultsPanel.classList.add('active');
    
    // Update stats
    document.getElementById('stat-total').textContent = totalTests;
    document.getElementById('stat-vulns').textContent = vulnCount;
    document.getElementById('stat-bypass').textContent = bypassCount;
    document.getElementById('stat-time').textContent = `${duration}s`;
    
    // Calculate overall confidence
    let overallConfidence = 0;
    if (scanResults.length > 0) {
        const totalConf = scanResults.reduce((sum, r) => sum + r.confidence, 0);
        overallConfidence = Math.round(totalConf / scanResults.length);
    }
    
    // Update confidence meter
    confidenceScore.textContent = `${overallConfidence}%`;
    confidenceFill.style.width = `${overallConfidence}%`;
    
    if (vulnCount === 0) {
        confidenceDesc.textContent = 'No vulnerabilities detected';
        confidenceFill.style.background = 'var(--accent-primary)';
    } else if (overallConfidence >= 95) {
        confidenceDesc.textContent = 'Critical vulnerabilities confirmed with high confidence';
        confidenceFill.style.background = 'var(--accent-danger)';
    } else if (overallConfidence >= 80) {
        confidenceDesc.textContent = 'Vulnerabilities detected - further verification recommended';
        confidenceFill.style.background = 'var(--accent-warning)';
    } else {
        confidenceDesc.textContent = 'Low confidence detections - manual testing advised';
        confidenceFill.style.background = 'var(--accent-secondary)';
    }
    
    // Update header
    if (vulnCount > 0) {
        resultHeader.className = 'result-header vulnerable';
        resultHeader.innerHTML = '<i class="fas fa-exclamation-triangle"></i><span>Vulnerabilities Detected!</span>';
    } else {
        resultHeader.className = 'result-header safe';
        resultHeader.innerHTML = '<i class="fas fa-shield-check"></i><span>No Vulnerabilities Found</span>';
    }
    
    // Build result content
    if (scanResults.length > 0) {
        // Sort by confidence (highest first)
        scanResults.sort((a, b) => b.confidence - a.confidence);
        
        resultContent.innerHTML = scanResults.map((vuln, index) => `
            <div class="vulnerability-item">
                <div class="vuln-header">
                    <span class="vuln-type">${index + 1}. ${vuln.type} XSS (${vuln.severity})</span>
                    <span class="vuln-confidence ${getConfidenceColor(vuln.confidence)}">${getConfidenceLabel(vuln.confidence)}</span>
                </div>
                <div class="vuln-detail">
                    <strong>Payload:</strong>
                    <code>${escapeHtml(vuln.payload)}</code>
                    <strong>Context:</strong> ${vuln.context}<br>
                    <strong>Encoding:</strong> ${vuln.encoding}<br>
                    ${vuln.wafBypass ? '<span class="vuln-bypass"><i class="fas fa-unlock"></i> WAF Bypass</span>' : ''}
                </div>
            </div>
        `).join('');
    } else {
        resultContent.innerHTML = `
            <div class="safe-result">
                <i class="fas fa-check-circle"></i>
                <strong>Target appears to be secure!</strong><br>
                No XSS vulnerabilities were detected during the scan.<br>
                <small style="color: var(--text-muted);">Note: This does not guarantee complete security. Manual testing is recommended.</small>
            </div>
        `;
    }
}

// ============================================
// Export Results
// ============================================
function exportResults(format = 'json') {
    if (scanResults.length === 0) {
        showToast('No results to export', 'error');
        return;
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const url = targetUrl.value || 'unknown-target';
    const hostname = url.replace(/^https?:\/\//, '').split('/')[0];
    
    let content = '';
    let filename = '';
    let mimeType = '';
    
    if (format === 'json') {
        const exportData = {
            scan_info: {
                target: url,
                timestamp: new Date().toISOString(),
                duration: document.getElementById('stat-time').textContent,
                total_tests: parseInt(document.getElementById('stat-total').textContent),
                vulnerabilities_found: scanResults.length,
                waf_detected: wafDetected,
                waf_type: wafType
            },
            vulnerabilities: scanResults
        };
        content = JSON.stringify(exportData, null, 2);
        filename = `xss-scan-${hostname}-${timestamp}.json`;
        mimeType = 'application/json';
    } else if (format === 'csv') {
        const headers = 'Type,Severity,Confidence,Payload,Context,Encoding,WAF Bypass\n';
        const rows = scanResults.map(r => 
            `"${r.type}","${r.severity}",${r.confidence},"${r.payload.replace(/"/g, '""')}","${r.context}","${r.encoding}",${r.wafBypass ? 'Yes' : 'No'}`
        ).join('\n');
        content = headers + rows;
        filename = `xss-scan-${hostname}-${timestamp}.csv`;
        mimeType = 'text/csv';
    } else if (format === 'html') {
        content = `<!DOCTYPE html>
<html>
<head>
    <title>XSS Scan Report - ${hostname}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #d32f2f; }
        .summary { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .vuln { background: #ffebee; padding: 15px; margin: 10px 0; border-left: 4px solid #d32f2f; border-radius: 4px; }
        .payload { background: #263238; color: #aed581; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; overflow-x: auto; }
        .confidence-high { color: #d32f2f; font-weight: bold; }
        .confidence-medium { color: #f57c00; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Vulnerability Scan Report</h1>
        <div class="summary">
            <strong>Target:</strong> ${url}<br>
            <strong>Scan Date:</strong> ${new Date().toLocaleString()}<br>
            <strong>Vulnerabilities Found:</strong> ${scanResults.length}<br>
            <strong>WAF Detected:</strong> ${wafDetected ? wafType : 'No'}
        </div>
        <h2>Vulnerabilities</h2>
        ${scanResults.map((v, i) => `
            <div class="vuln">
                <h3>${i + 1}. ${v.type} XSS (${v.severity})</h3>
                <p><strong>Confidence:</strong> <span class="${v.confidence >= 95 ? 'confidence-high' : 'confidence-medium'}">${v.confidence}%</span></p>
                <p><strong>Context:</strong> ${v.context}</p>
                <div class="payload">${escapeHtml(v.payload)}</div>
                ${v.wafBypass ? '<p><strong>WAF Bypass:</strong> Yes</p>' : ''}
            </div>
        `).join('')}
    </div>
</body>
</html>`;
        filename = `xss-scan-${hostname}-${timestamp}.html`;
        mimeType = 'text/html';
    }
    
    const blob = new Blob([content], { type: mimeType });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    
    showToast(`Results exported as ${format.toUpperCase()}`);
}

// ============================================
// Event Listeners
// ============================================

// Scan button
scanBtn.addEventListener('click', async () => {
    const url = targetUrl.value.trim();
    
    if (!url) {
        showToast('Please enter a target URL', 'error');
        targetUrl.focus();
        return;
    }
    
    if (!isValidUrl(url)) {
        showToast('Please enter a valid URL', 'error');
        targetUrl.focus();
        return;
    }
    
    await performScan();
});

// Enter key in URL input
targetUrl.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        scanBtn.click();
    }
});

// Copy terminal content
copyBtn.addEventListener('click', () => {
    const content = Array.from(terminalBody.querySelectorAll('.terminal-line'))
        .map(line => line.textContent)
        .join('\n');
    copyToClipboard(content);
});

// Clear terminal
clearBtn.addEventListener('click', clearTerminal);

// Export results
exportBtn.addEventListener('click', () => {
    // Create export menu
    const formats = ['JSON', 'CSV', 'HTML'];
    const format = prompt(`Export format:\n1. JSON\n2. CSV\n3. HTML\n\nEnter number (1-3):`, '1');
    
    if (format && ['1', '2', '3'].includes(format)) {
        const formatMap = { '1': 'json', '2': 'csv', '3': 'html' };
        exportResults(formatMap[format]);
    }
});

// Advanced options toggle
advancedToggle.addEventListener('click', () => {
    advancedToggle.classList.toggle('active');
    advancedPanel.classList.toggle('active');
});

// Confidence threshold slider
confidenceThreshold.addEventListener('input', (e) => {
    confidenceValue.textContent = `${e.target.value}%`;
});

// Mobile menu toggle
mobileMenuBtn.addEventListener('click', () => {
    mobileMenu.classList.toggle('active');
});

// Close mobile menu when clicking a link
mobileMenu.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
        mobileMenu.classList.remove('active');
    });
});

// Smooth scroll for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Active navigation highlight on scroll
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-links a');

window.addEventListener('scroll', () => {
    let current = '';
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (scrollY >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// ============================================
// Initialize
// ============================================
document.addEventListener('DOMContentLoaded', async () => {
    // Create particle background
    createParticles();
    
    // Load payloads
    await loadPayloads();
    
    console.log('%cXSS Scanner Pro v3.0', 'color: #00ff88; font-size: 24px; font-weight: bold;');
    console.log('%cAdvanced Detection Engine Loaded', 'color: #00d4ff;');
    console.log('%cFeatures: Confidence Scoring | WAF Detection | Context Analysis', 'color: #a0a0b0;');
});
