-- MalGuard AI Database Schema Initializer
-- Execute this script in your Supabase SQL Editor.

-- Drop tables if they exist
drop table if exists scans;
drop table if exists users;

-- 1. Users Table Definition
create table users (
    id uuid default gen_random_uuid() primary key,
    email text unique not null,
    password_hash text not null,
    role text default 'user' not null check (role in ('user', 'admin')),
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Indexing for email-based login lookups
create index idx_users_email on users(email);

-- 2. Scans Table Definition
create table scans (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade not null,
    filename text not null,
    file_size integer not null,
    sha256 text not null,
    md5 text not null,
    entropy double precision not null,
    num_sections integer not null,
    compile_timestamp timestamp with time zone,
    prediction text not null,
    threat_score integer not null check (threat_score >= 0 and threat_score <= 100),
    confidence_score double precision not null,
    mitre_mapping jsonb not null default '[]'::jsonb,
    ioc_summary jsonb not null default '{}'::jsonb,
    suspicious_apis text[] not null default '{}'::text[],
    imported_dlls text[] not null default '{}'::text[],
    entropy_analysis jsonb not null default '{}'::jsonb,
    section_analysis jsonb not null default '[]'::jsonb,
    recommended_mitigations text[] not null default '{}'::text[],
    feature_importance jsonb not null default '{}'::jsonb,
    virustotal_data jsonb,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Indexing for dashboard analysis searches and lookups
create index idx_scans_user_id on scans(user_id);
create index idx_scans_prediction on scans(prediction);
create index idx_scans_sha256 on scans(sha256);
create index idx_scans_md5 on scans(md5);
create index idx_scans_created_at on scans(created_at desc);

-- Enable Row Level Security (RLS) or add standard policies if needed
-- For ease of setup, RLS can be managed from the Supabase Dashboard
