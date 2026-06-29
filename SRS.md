# Software Requirements Specification (SRS)

**Project Name:** MallnSight
**Tagline:** Static Malware Analysis & Threat Intelligence Platform
**Repository:** https://github.com/vibushasatheeshkumar/mallnsight

---

## 1. Introduction

### 1.1 Purpose

This document describes what MallnSight is supposed to do. It lists the
features the system provides and the conditions it must follow, so
anyone reading it can understand the project without looking at the
code.

### 1.2 Project Overview

MallnSight is a web application that lets a user upload a file (like an
`.exe` or `.dll`) and checks it for signs of malware **without running
the file**. It only reads and inspects the file, then shows the results
on a dashboard and lets the user download a PDF report.

### 1.3 Intended Users

- Students learning about malware analysis
- Security enthusiasts who want to quickly check a suspicious file
- Anyone who wants a simple, free, offline tool for static file analysis

---

## 2. Overall Description

### 2.1 What the System Does

1. User uploads a file from the browser.
2. The system checks the file is allowed (type and size).
3. The system analyzes the file using several techniques.
4. The system shows a risk score and a verdict (Clean / Low Risk /
   Suspicious / High Risk).
5. The user can download all the results as a PDF report.

### 2.2 What the System Does NOT Do

- It does **not** run or open the uploaded file.
- It does **not** send the uploaded file itself anywhere else. (A small
  summary — hashes, score, verdict — is optionally saved to a cloud
  database for the History page; see below.)

### 2.3 Tools & Technologies Used

| Part | Technology |
|---|---|
| Backend | Python, Flask |
| File analysis | pefile, yara-python |
| Cloud database | MongoDB Atlas (optional, for analysis history) |
| Report generation | reportlab (PDF) |
| Frontend | HTML, CSS, Bootstrap, JavaScript |
| Hosting | Render (free tier) |

---

## 3. Functional Requirements

These are the things the system must be able to do.

| No. | Requirement |
|---|---|
| 1 | Allow the user to upload a file through the Upload page. |
| 2 | Reject the upload if no file is selected. |
| 3 | Reject files that are not in the allowed list (.exe, .dll, .sys, .msi, .zip, .apk, .pdf, .docx, .bin). |
| 4 | Reject files larger than 100 MB. |
| 5 | Calculate MD5, SHA1, and SHA256 hashes of the file. |
| 6 | Show basic file information (name, size, type). |
| 7 | Analyze the file structure if it is a Windows executable (PE file). |
| 8 | Calculate the entropy of the file (used to detect packed/encrypted files). |
| 9 | Extract readable text (strings) from the file and highlight suspicious ones. |
| 10 | Scan the file using YARA rules to detect known malware patterns. |
| 11 | Combine all results into one risk score (0–100) and a verdict. |
| 12 | Display all results on a dashboard page. |
| 13 | Let the user download a PDF report of the results. |
| 14 | Save a summary of each analysis (hashes, score, verdict) to a cloud database (MongoDB Atlas), if configured. |
| 15 | Show a History page listing past analyses from the cloud database. |
| 16 | Show extra pages: Home, Features, Documentation, History, Contact. |

---

## 4. Non-Functional Requirements

These describe how well the system should work.

| No. | Requirement |
|---|---|
| 1 | The analysis should finish within a few seconds for normal-sized files. |
| 2 | The uploaded file must never be executed by the system. |
| 3 | The website should work well on both mobile and desktop screens. |
| 4 | The system should still work (with a small warning) even if YARA is not installed. |
| 5 | The code should be easy to extend (e.g., adding new YARA rules without changing code). |

---

## 5. System Workflow (Simple Steps)

```
User uploads file
        │
        ▼
File is checked (type & size)
        │
        ▼
Hashing → Metadata → PE Analysis → Entropy → Strings → YARA Scan
        │
        ▼
Risk Score & Verdict calculated
        │
        ▼
Summary saved to cloud database (MongoDB Atlas, optional)
        │
        ▼
Dashboard shown to user
        │
        ▼
User downloads PDF report (optional)
```

---

## 6. Limitations

- Only a summary (hashes, score, verdict) is saved to the cloud
  database — the full breakdown (PE info, strings, YARA matches) is not
  saved, so a past dashboard view can't be reopened from History.
- The History feature requires a MongoDB Atlas connection string to be
  configured; without it, the History page simply shows "unavailable"
  and the rest of the app still works normally.
- Works best with Windows executable files (PE files); other file types
  get limited analysis.
- Free hosting (Render) may be slow to wake up after being idle.
- No user login — History shows everyone's past analyses, not per-user.

---

## 7. Future Scope

- Support more file types (PDF, ZIP, APK in more detail).
- Save the full analysis result (not just a summary) to the cloud
  database, so past results can be reopened in full.
- Add user login system.
- Add option for sandboxed (safe) dynamic analysis.

---

## 8. Conclusion

MallnSight is a simple, beginner-friendly tool that automates the basic
steps of malware static analysis (hashing, file inspection, entropy,
string extraction, and YARA scanning) and presents the results clearly
on a web dashboard with a downloadable PDF report — all without ever
running the uploaded file.

---

*End of Document.*
