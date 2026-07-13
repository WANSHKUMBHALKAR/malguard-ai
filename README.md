# MalGuard AI - AI Malware Detection Platform

MalGuard AI is a complete, production-ready Windows Portable Executable (PE) static analysis and malware classification platform. It uses Next.js 15, FastAPI, and machine learning models to detect threats and generate details.

## Stack
- **Frontend**: Next.js 15, TypeScript, TailwindCSS, shadcn/ui, Framer Motion, Recharts
- **Backend**: FastAPI (Python serverless functions on Vercel)
- **Database**: Supabase PostgreSQL
- **ML Framework**: scikit-learn (Random Forest, Extra Trees, Gradient Boosting), pandas, numpy, joblib, pefile

---

## 1. Supabase Schema Setup

Execute the following SQL commands inside the Supabase Query Editor to create the necessary tables:

```sql
-- Users table
create table users (
    id uuid default gen_random_uuid() primary key,
    email text unique not null,
    password_hash text not null,
    role text default 'user' not null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Scans history table
create table scans (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade,
    filename text not null,
    file_size integer not null,
    sha256 text not null,
    md5 text not null,
    entropy double precision not null,
    num_sections integer not null,
    compile_timestamp timestamp with time zone,
    prediction text not null,
    threat_score integer not null,
    confidence_score double precision not null,
    mitre_mapping jsonb not null,
    ioc_summary jsonb not null,
    suspicious_apis text[] not null,
    imported_dlls text[] not null,
    entropy_analysis jsonb not null,
    section_analysis jsonb not null,
    recommended_mitigations text[] not null,
    feature_importance jsonb not null,
    virustotal_data jsonb,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);
```

---

## 2. Installation and Running Locally

### Prerequisites
- Node.js (v18+)
- Python (3.9+)

### Frontend Setup
1. Install node modules:
   ```bash
   npm install
   ```
2. Setup environment variables by copying `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```

### Backend Setup
1. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```
2. Install Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the backend development server:
   ```bash
   uvicorn api.index:app --port 8000 --reload
   ```

---

## 3. Training the Machine Learning Model

Before running predictions, you must train the classifier. 

1. Download a PE malware dataset (like BODMAS or Kaggle PE malware dataset), or run the dataset downloader script:
   ```bash
   python scripts/download_dataset.py
   ```
2. Execute the model training pipeline:
   ```bash
   python api/training.py
   ```
   This will:
   - Train Random Forest, Extra Trees, and Gradient Boosting.
   - Output evaluation metrics (Accuracy, F1-score).
   - Save the best model to `models/malware_detector.joblib`.
   - Export a beautiful training report PDF to `models/training_report.pdf`.

---

## 4. Deploying to Vercel

1. Install the Vercel CLI: `npm install -g vercel`.
2. Configure environment variables in the Vercel dashboard:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `JWT_SECRET`
   - `JWT_ALGORITHM`
   - `ACCESS_TOKEN_EXPIRE_MINUTES`
   - `VIRUSTOTAL_API_KEY` (Optional)
3. Build and deploy:
   ```bash
   vercel --prod
   ```
