# MallnSight — User Guide

A simple how-to guide for using MallnSight to analyze a file. No
technical background is required to follow this guide.

---

## 1. What Is MallnSight?

MallnSight is a website that checks a file (like a `.exe` or `.dll`) for
signs of malware. It does **not** run or open your file — it only reads
it and reports what it finds.

---

## 2. Opening the Website

- If you're using the hosted version, just open the link in your
  browser (e.g. `https://mallnsight.onrender.com`).
- If you're running it yourself, open `http://127.0.0.1:5000` after
  starting the app (see [README.md](README.md) for setup steps).

---

## 3. Step-by-Step: Analyzing a File

### Step 1 — Go to the Upload Page

Click **"Analyze File"** in the top navigation bar, or go directly to
the **Upload** page.

### Step 2 — Choose a File

You can either:

- **Drag and drop** your file onto the upload box, or
- Click **"Browse File"** and select a file from your computer.

**Supported file types:** `.exe`, `.dll`, `.sys`, `.msi`, `.zip`,
`.apk`, `.pdf`, `.docx`, `.bin`

**Maximum file size:** 100 MB

### Step 3 — Start the Investigation

Once a file is selected, you'll see its name appear below the upload
box. Click **"Start Investigation"** to begin the analysis.

> This may take a few seconds, depending on the file size.

### Step 4 — Read the Results

You'll be taken to a **dashboard** showing:

| Section | What It Means |
|---|---|
| **Verdict banner** | A quick summary: `CLEAN`, `LOW RISK`, `SUSPICIOUS`, or `HIGH RISK`, with a risk score out of 100 |
| **File Information** | Filename, size, type |
| **Hashes** | Unique fingerprints (MD5, SHA1, SHA256) of the file — click **Copy** next to any hash to copy it |
| **PE Analysis** | Technical details about the file's structure (only shown for Windows executable files) |
| **YARA Matches** | Known malicious patterns found in the file, if any |
| **File Entropy** | How "random" the file's data looks — high entropy can mean the file is packed or encrypted |
| **Suspicious Strings** | Text found inside the file that is commonly associated with malware behavior |

### Step 5 — Download the Report (Optional)

Click **"Download PDF Report"** at the bottom of the dashboard to save
all these results as a PDF file you can share or keep for your records.

---

## 4. Understanding the Risk Score

| Score Range | Verdict | Meaning |
|---|---|---|
| 0 – 14 | **CLEAN** | No suspicious indicators found |
| 15 – 39 | **LOW RISK** | A few minor indicators found |
| 40 – 69 | **SUSPICIOUS** | Multiple indicators found — investigate further |
| 70 – 100 | **HIGH RISK** | Strong evidence of malicious behavior |

> **Note:** A high score is not 100% proof a file is malware, and a low
> score is not a guarantee a file is safe. MallnSight is a triage tool —
> always use additional judgment and tools for important decisions.

---

## 5. Other Pages

| Page | What's There |
|---|---|
| **Home** | Overview of what MallnSight does |
| **Features** | Full list of analysis capabilities |
| **Documentation** | Technical details about how the tool works |
| **History** | A log of past analyses (filename, hashes, score, verdict) saved to the cloud, so they're still visible even after the local report files are gone |
| **Contact** | Email, GitHub, and LinkedIn links to reach the developer |

---

## 6. Frequently Asked Questions

**Is my file uploaded anywhere else?**
No. The file itself is only ever read on the server you're connected
to and is never sent anywhere else. A small text summary of the
result (hashes, score, verdict — not the file) may be saved to a
cloud database so it shows up on the History page; that's the only
data that leaves the server.

**Will the file be executed/opened?**
No. MallnSight only reads the file's raw bytes. It never runs it.

**What if I upload a file type that isn't a Windows executable?**
Basic info (hashes, size, entropy, strings) will still be shown, but the
"PE Analysis" section will note that the file isn't a recognized PE
file.

**Why does the YARA Matches section say "unavailable"?**
This happens only on certain setups where the YARA scanning library
isn't installed. Every other part of the analysis still works normally.

**Why does the History page say "unavailable"?**
This happens when the optional cloud database isn't configured on this
particular instance. The rest of the site, including analyzing files,
still works normally — History is just an extra, optional feature.
