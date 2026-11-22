-- =========================================================
-- NOOR PREMIUM — INITIAL CATALOG SEED DATA
-- Migration: 0002_seed_catalog.sql
-- Safe to re-run via INSERT OR IGNORE
-- =========================================================

PRAGMA foreign_keys = ON;

INSERT OR IGNORE INTO movies (
  id, slug, title, original_title, synopsis, release_year, rating, age_rating,
  runtime_minutes, genres_json, languages_json, country, poster_url, backdrop_url,
  trailer_url, sources_json, subtitles_json, status, featured, trending, popular,
  latest, recommended, related_ids_json
) VALUES
(
  'mov-001',
  'ratrer-chhaya',
  'রাতের ছায়া',
  'Shadow of the Night',
  'একটি প্রাচীন শহরের গোপন রহস্য উন্মোচনে বের হওয়া অনুসন্ধানীর গল্প—যেখানে প্রতিটি ছায়ায় লুকিয়ে আছে নতুন সত্য।',
  2026,
  8.9,
  'PG-13',
  128,
  '["Mystery","Thriller","Drama"]',
  '["বাংলা","English"]',
  'Bangladesh',
  './assets/images/posters/ratrer-chhaya.webp',
  './assets/images/backdrops/ratrer-chhaya-bg.webp',
  '',
  '[]',
  '[]',
  'published',
  1,
  1,
  1,
  1,
  1,
  '["ser-001","mov-002"]'
),
(
  'mov-002',
  'shunno-digonto',
  'শূন্য দিগন্ত',
  'Zero Horizon',
  'দূর মহাকাশে হারিয়ে যাওয়া একটি গবেষণা অভিযানের শেষ সংকেত এবং পৃথিবীতে ফেরার অদম্য সংগ্রাম।',
  2026,
  8.6,
  'PG-13',
  142,
  '["Sci-Fi","Adventure"]',
  '["বাংলা","English"]',
  'International',
  './assets/images/posters/shunno-digonto.webp',
  './assets/images/backdrops/shunno-digonto-bg.webp',
  '',
  '[]',
  '[]',
  'published',
  0,
  1,
  1,
  1,
  1,
  '["mov-001","ser-002"]'
),
(
  'mov-003',
  'aranyer-dinratri',
  'অরণ্যের দিনরাত্রি',
  'Days & Nights in the Woods',
  'প্রকৃতির কোলে কাটানো চার বন্ধুর জীবনের মোড় ঘোরানো ভ্রমণ ও আত্মোপলব্ধির গল্প।',
  2025,
  8.3,
  'PG',
  112,
  '["Drama","Adventure"]',
  '["বাংলা"]',
  'Bangladesh',
  './assets/images/posters/aranyer-dinratri.webp',
  './assets/images/backdrops/aranyer-dinratri-bg.webp',
  '',
  '[]',
  '[]',
  'published',
  0,
  0,
  0,
  1,
  0,
  '["mov-002"]'
),
(
  'mov-004',
  'cyber-pulse-2099',
  'সাইবার পালস ২০৯৯',
  'Cyber Pulse 2099',
  'ভবিষ্যতের মেগাসিটিতে কৃত্রিম বুদ্ধিমত্তা ও মানবিক সিদ্ধান্তের সংঘাত নিয়ে অ্যাকশন-সাই-ফাই কাহিনি।',
  2026,
  8.5,
  'PG-13',
  121,
  '["Sci-Fi","Action","Thriller"]',
  '["English","বাংলা"]',
  'International',
  './assets/images/posters/cyber-pulse-2099.webp',
  './assets/images/backdrops/cyber-pulse-2099-bg.webp',
  '',
  '[]',
  '[]',
  'published',
  0,
  1,
  1,
  0,
  1,
  '["mov-002"]'
);

INSERT OR IGNORE INTO series (
  id, slug, title, original_title, synopsis, release_year, rating, age_rating,
  series_status, genres_json, languages_json, country, poster_url, backdrop_url,
  trailer_url, status, featured, trending, popular, latest, recommended, related_ids_json
) VALUES
(
  'ser-001',
  'noor-chronicles',
  'নূর ক্রনিকলস',
  'Noor Chronicles',
  'সময় ও স্মৃতির সীমান্তে দাঁড়িয়ে থাকা এক পরিবারের অজানা অধ্যায়গুলো নিয়ে নির্মিত প্রিমিয়াম ড্রামা সিরিজ।',
  2026,
  9.2,
  'TV-14',
  'ongoing',
  '["Drama","Mystery"]',
  '["বাংলা"]',
  'Bangladesh',
  './assets/images/posters/noor-chronicles.webp',
  './assets/images/backdrops/noor-chronicles-bg.webp',
  '',
  'published',
  0,
  1,
  1,
  0,
  1,
  '["mov-001","ser-002"]'
),
(
  'ser-002',
  'dhaka-noir',
  'ঢাকা নয়ার',
  'Dhaka Noir',
  'বৃষ্টিভেজা রাতের শহরের অপরাধ ও ন্যায়বিচারের টানাপোড়েনে গড়ে ওঠা থ্রিলার সিরিজ।',
  2025,
  8.7,
  'TV-MA',
  'completed',
  '["Thriller","Crime","Drama"]',
  '["বাংলা","English"]',
  'Bangladesh',
  './assets/images/posters/dhaka-noir.webp',
  './assets/images/backdrops/dhaka-noir-bg.webp',
  '',
  'published',
  0,
  0,
  1,
  1,
  1,
  '["mov-001","ser-001"]'
);

INSERT OR IGNORE INTO seasons (id, series_id, season_number, title) VALUES
('sea-101', 'ser-001', 1, 'Season 1'),
('sea-201', 'ser-002', 1, 'Season 1');

INSERT OR IGNORE INTO episodes (
  id, season_id, episode_number, title, synopsis, runtime_minutes, thumbnail_url, sources_json, subtitles_json
) VALUES
(
  'ep-101-01',
  'sea-101',
  1,
  'অজানা সংকেত',
  'প্রথম পর্বে রহস্যের সূচনা হয় একটি পুরোনো ডায়েরি থেকে।',
  46,
  './assets/images/backdrops/ep-101-01.webp',
  '[]',
  '[]'
);
