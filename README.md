# QRShield AI
### Intelligent QR Code Phishing Detection System Using Machine Learning

A B.Tech 3rd-year AIML project: scan a QR code (webcam, upload, or manual
URL), decode it, and classify the destination URL as **SAFE**,
**SUSPICIOUS**, or **PHISHING** using a trained Random Forest model.

---

## 1. What's actually in this repo

Everything below is real, working code that has been run and tested in
the process of building this project — not placeholder scaffolding.

| Folder | Contents |
|---|---|
| `Dataset/` | `generate_dataset.py` — builds the labeled feature dataset |
| `Models/` | `train_model.py` — trains & compares 4 algorithms, saves `model.pkl` |
| `Backend/` | Flask REST API, feature extraction, QR decoding |
| `Database/` | SQLite schema + query helpers |
| `Frontend/` | React (Vite) single-page app, 8 pages |
| `Documentation/` | (see note at the bottom — diagrams/report to follow) |

## 2. An honest note about the dataset

**This build environment has no internet access**, so the real Kaggle
phishing-URL dataset could not be downloaded here. `generate_dataset.py`
instead synthesizes ~6,000 URLs whose feature distributions mirror the
well-known UCI/Kaggle phishing-URL feature schema (phishing URLs skew
toward no-HTTPS, IP hosts, long URLs, suspicious keywords; legitimate
URLs skew the opposite way), including realistic label noise so the
model isn't trivially perfect. The **entire ML pipeline — training,
cross-validation, hyperparameter tuning, metrics — is genuinely run on
this data**, only the source URLs are synthetic rather than scraped.

**Before your final submission**, swap in the real dataset:
1. Download a phishing URL dataset from Kaggle, e.g.
   [Phishing Website Detector](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)
   (any CSV with `url` and `label` columns works).
2. Save it as `Dataset/phishing_raw.csv`.
3. Run:
   ```bash
   cd Dataset
   python generate_dataset.py --from-csv phishing_raw.csv
   ```
4. Retrain: `cd ../Models && python train_model.py`

No other code changes are needed — `feature_extraction.py` is shared
between training and live prediction, so the model and the API always
agree on feature definitions.

## 3. Installation & running locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- A webcam (only needed for the live-scan page)

### Step 1 — Backend + ML model
```bash
cd Backend
pip install -r requirements.txt

# Generate the dataset and train the model (first time only)
cd ../Dataset
python generate_dataset.py
cd ../Models
python train_model.py

# Start the API server
cd ../Backend
python app.py
```
The backend runs at `http://localhost:5000`. Verify with:
```bash
curl http://localhost:5000/api/health
```

### Step 2 — Frontend
```bash
cd Frontend
npm install
npm run dev
```
Open `http://localhost:3000` in your browser. The webcam scanner needs
camera permission and works best over `localhost` or HTTPS (browsers
block camera access on plain HTTP for non-localhost origins).

### Step 3 — Try it
- **Paste URL**: try `http://192.168.1.5/login-verify-account.php` (flagged PHISHING)
  and `https://www.wikipedia.org` (flagged SAFE).
- **Upload QR**: generate a QR code online for any URL and upload the image.
- **Scan QR**: hold a QR code up to your webcam.
- **Dashboard** and **History** populate automatically as you scan.

## 4. API reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness check |
| POST | `/api/analyze-url` | `{"url": "...", "source": "manual"}` → prediction |
| POST | `/api/scan-qr` | Multipart image upload → decode + prediction |
| GET | `/api/history?limit=200` | Scan history |
| GET | `/api/dashboard` | Aggregated counts + recent activity |

## 5. Model performance (on the current synthetic dataset)

See `Models/model_metadata.json` for exact numbers and
`Models/confusion_matrix.png`, `Models/roc_curve.png`,
`Models/feature_importance.png` for the visualizations requested in the
project brief. Random Forest was selected as the best-performing model
after 5-fold cross-validation and grid-search hyperparameter tuning,
with ~96% accuracy and F1 score on held-out test data.

## 6. Known limitations (state these honestly in your viva)

- The model is a **statistical estimate based on URL structure**, not a
  live threat-intelligence system — it doesn't check page content,
  certificate reputation, or blocklists.
- It is trained on a dataset that (until you swap in the real Kaggle
  CSV per §2) is synthetically generated to mirror real-world patterns,
  not scraped phishing reports.
- QR decoding uses OpenCV's built-in `QRCodeDetector` rather than
  `pyzbar`, since this sandbox couldn't install `pyzbar`; either works,
  and OpenCV avoids an extra system dependency (`libzbar`) for graders
  running this on their own machine.

## 7. Documentation still to come

Given the scope of this brief (IEEE-format research paper, PPT, ER
diagram, DFD levels 0/1, use-case diagram, sequence diagram, activity
diagram, architecture diagram, full installation guide as a standalone
doc), those are best generated as a focused follow-up once you've
confirmed this working app matches what you need for your submission —
happy to produce all of them next.
