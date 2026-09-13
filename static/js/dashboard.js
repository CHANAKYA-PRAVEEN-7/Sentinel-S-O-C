/**
 * SentinelSOC - Global Dashboard Utilities
 */

// Utility: Copy IP Address to Clipboard
function copyIpToClipboard(ip) {
    if (!navigator.clipboard) {
        fallbackCopyTextToClipboard(ip);
        return;
    }
    navigator.clipboard.writeText(ip).then(function() {
        if (typeof showToast === 'function') {
            showToast(`Copied IP: ${ip}`, 'info');
        }
    }, function(err) {
        console.error('Could not copy IP: ', err);
    });
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        if (typeof showToast === 'function') {
            showToast(`Copied: ${text}`, 'info');
        }
    } catch (err) {
        console.error('Fallback copy failed', err);
    }
    document.body.removeChild(textArea);
}

// Utility: Export table data to CSV
function exportTableToCSV(tableId, filename = 'sentinelsoc_export.csv') {
    const table = document.getElementById(tableId);
    if (!table) return;

    let csv = [];
    const rows = table.querySelectorAll('tr');

    for (let i = 0; i < rows.length; i++) {
        const row = [];
        const cols = rows[i].querySelectorAll('td, th');
        for (let j = 0; j < cols.length; j++) {
            // Exclude action buttons
            if (cols[j].classList.contains('text-end')) continue;
            let text = cols[j].innerText.replace(/"/g, '""').trim();
            row.push(`"${text}"`);
        }
        if (row.length > 0) csv.push(row.join(','));
    }

    const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
    const downloadLink = document.createElement('a');
    downloadLink.download = filename;
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = 'none';
    document.body.appendChild(downloadLink);
    downloadLink.click();
    downloadLink.remove();
}
