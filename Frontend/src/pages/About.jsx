import React from 'react'

export default function About() {
  return (
    <div className="page-container" style={{ maxWidth: 760 }}>
      <span className="eyebrow">Methodology</span>
      <h1 style={{ marginTop: 10, fontSize: '1.9rem' }}>About QRShield AI</h1>

      <p style={{ marginTop: 20 }}>
        QRShield AI is a B.Tech AIML academic project demonstrating an end-to-end
        machine learning pipeline for phishing URL detection, wrapped in a QR-code
        scanning workflow. It decodes QR codes from a webcam feed, an uploaded image,
        or manual text entry, extracts thirteen structural features from the resulting
        URL, and classifies it using a Random Forest model as SAFE, SUSPICIOUS, or
        PHISHING.
      </p>

      <h3 style={{ marginTop: 32, fontSize: '1.15rem' }}>How the model was trained</h3>
      <p style={{ marginTop: 10 }}>
        Four algorithms — Logistic Regression, Decision Tree, Random Forest, and
        Gradient Boosting — were trained on the same feature set, cross-validated with
        5-fold CV, and compared on accuracy, precision, recall, and F1 score. Random
        Forest was selected after hyperparameter tuning via grid search. Full metrics,
        the confusion matrix, ROC curve, and feature importance chart are saved
        alongside the trained model in the Models/ folder.
      </p>

      <h3 style={{ marginTop: 32, fontSize: '1.15rem' }}>Limitations, honestly stated</h3>
      <p style={{ marginTop: 10 }}>
        This is not a claim that the model can detect every phishing website. It
        reasons only from lexical and structural properties of a URL — it does not
        check live threat-intelligence feeds, page content, or certificate reputation.
        Sophisticated phishing pages that mimic legitimate URL structure closely can
        still evade detection, and legitimate but unusually-formed URLs can be
        flagged as suspicious. Treat the risk score as one input to your judgment,
        not a final verdict.
      </p>

      <h3 style={{ marginTop: 32, fontSize: '1.15rem' }}>The 13 features used</h3>
      <ul style={{ marginTop: 10, paddingLeft: 20, color: 'var(--text-muted)', lineHeight: 2 }}>
        <li>URL length &amp; domain length</li>
        <li>HTTPS presence</li>
        <li>Dot count, digit count, hyphen count, special character count</li>
        <li>Subdomain count</li>
        <li>Raw IP address usage</li>
        <li>Known URL-shortener detection</li>
        <li>Suspicious keyword count (login, verify, secure, update, bank, account, password, ...)</li>
        <li>Top-level domain reputation flag</li>
        <li>'@' symbol presence (a known redirection trick)</li>
      </ul>
    </div>
  )
}
