# Analyze CSP Violations

Parses large CSV audit log exports from Microsoft Purview, extracts CSP violation data (DocumentUrl / BlockedUrl), aggregates violations by blocked domain, and generates a standalone interactive HTML report for SharePoint Administrators.

> **Related Message Center notification:** [MC1193419](https://admin.microsoft.com/Adminportal/Home#/MessageCenter) — SharePoint Online Content Security Policy enforcement changes.

## Scripts Included

### 1. Analyze-CSPViolations.ps1
Analyzes standard CSP violations from Microsoft Purview audit logs and generates interactive HTML reports.

- **Script**: [Analyze-CSPViolations.ps1](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/Analyze-CSPViolations.ps1)
- **Documentation**: [README-Analyze-CSPViolations.md](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/README-Analyze-CSPViolations.md)

### 2. Analyze-CSPInlineViolations.ps1
Analyzes inline CSP violations from Microsoft Purview audit logs and generates interactive HTML reports.

- **Script**: [Analyze-CSPInlineViolations.ps1](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/Analyze-CSPInlineViolations.ps1)
- **Documentation**: [README-Analyze-InlineCSPViolations.md](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/README-Analyze-InlineCSPViolations.md)

## Quick Links

- [View Analyze-CSPViolations.ps1](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/Analyze-CSPViolations.ps1)
- [View Analyze-CSPInlineViolations.ps1](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/Analyze-CSPInlineViolations.ps1)
- [Read CSP Violations Documentation](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/README-Analyze-CSPViolations.md)
- [Read Inline CSP Violations Documentation](https://github.com/mikelee1313/Analyze-CSPViolations/blob/main/README-Analyze-InlineCSPViolations.md)

## Getting Started

1. Choose the script that matches your needs:
   - Use **Analyze-CSPViolations.ps1** for standard CSP violations
   - Use **Analyze-CSPInlineViolations.ps1** for inline CSP violations

2. Review the corresponding README file for detailed instructions

3. Export your audit logs from Microsoft Purview as a CSV file

4. Run the appropriate script with your CSV file as input


## More Information

**Video: Introduction to Content Security Policy (CSP) in SharePoint Online**

[![Watch the video](https://i.ytimg.com/vi/OOFQQJTtAkM/hqdefault.jpg)](https://youtu.be/OOFQQJTtAkM)

