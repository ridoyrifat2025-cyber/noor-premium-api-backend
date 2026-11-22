/* =========================================================
   NOOR PREMIUM — CATALOG API ROUTES (PHASE 14)
   GET /api/v1/catalog, GET /api/v1/catalog/:id, GET /api/v1/series/:id/seasons
   ========================================================= */

import { jsonSuccess, jsonError } from "../lib/http.js";

function parseJsonArray(raw, fallback = []) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "string" || !raw.trim()) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (_) {
    return fallback;
  }
}

function mapMovieRow(row) {
  return {
    id: row.id,
    slug: row.slug,
    type: "movie",
    title: row.title,
    originalTitle: row.original_title || "",
    synopsis: row.synopsis || "",
    releaseYear: row.release_year,
    rating: row.rating,
    ageRating: row.age_rating || "PG-13",
    runtimeMinutes: row.runtime_minutes,
    genres: parseJsonArray(row.genres_json),
    languages: parseJsonArray(row.languages_json),
    country: row.country || "",
    posterUrl: row.poster_url || "",
    backdropUrl: row.backdrop_url || "",
    trailerUrl: row.trailer_url || "",
    sources: parseJsonArray(row.sources_json),
    subtitles: parseJsonArray(row.subtitles_json),
    status: row.status,
    featured: Boolean(row.featured),
    trending: Boolean(row.trending),
    popular: Boolean(row.popular),
    latest: Boolean(row.latest),
    recommended: Boolean(row.recommended),
    relatedIds: parseJsonArray(row.related_ids_json)
  };
}

function mapSeriesRow(row, seasons = []) {
  return {
    id: row.id,
    slug: row.slug,
    type: "series",
    title: row.title,
    originalTitle: row.original_title || "",
    synopsis: row.synopsis || "",
    releaseYear: row.release_year,
    rating: row.rating,
    ageRating: row.age_rating || "TV-14",
    seriesStatus: row.series_status || "ongoing",
    genres: parseJsonArray(row.genres_json),
    languages: parseJsonArray(row.languages_json),
    country: row.country || "",
    posterUrl: row.poster_url || "",
    backdropUrl: row.backdrop_url || "",
    trailerUrl: row.trailer_url || "",
    status: row.status,
    featured: Boolean(row.featured),
    trending: Boolean(row.trending),
    popular: Boolean(row.popular),
    latest: Boolean(row.latest),
    recommended: Boolean(row.recommended),
    relatedIds: parseJsonArray(row.related_ids_json),
    seasons
  };
}

async function loadSeriesSeasonsAndEpisodes(db, seriesId) {
  const seasonsRes = await db
    .prepare(
      `SELECT id, series_id, season_number, title
       FROM seasons
       WHERE series_id = ?1
       ORDER BY season_number ASC`
    )
    .bind(seriesId)
    .all();

  const seasonRows = (seasonsRes && seasonsRes.results) || [];
  const seasons = [];

  for (const s of seasonRows) {
    const epRes = await db
      .prepare(
        `SELECT id, season_id, episode_number, title, synopsis, runtime_minutes,
                thumbnail_url, sources_json, subtitles_json
         FROM episodes
         WHERE season_id = ?1
         ORDER BY episode_number ASC`
      )
      .bind(s.id)
      .all();

    const episodes = ((epRes && epRes.results) || []).map((ep) => ({
      id: ep.id,
      seasonId: ep.season_id,
      episodeNumber: ep.episode_number,
      title: ep.title,
      synopsis: ep.synopsis || "",
      runtimeMinutes: ep.runtime_minutes,
      thumbnailUrl: ep.thumbnail_url || "",
      sources: parseJsonArray(ep.sources_json),
      subtitles: parseJsonArray(ep.subtitles_json)
    }));

    seasons.push({
      id: s.id,
      seriesId: s.series_id,
      seasonNumber: s.season_number,
      title: s.title,
      episodes
    });
  }

  return seasons;
}

export async function handleListCatalog(request, env) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const url = new URL(request.url);
  const typeParam = (url.searchParams.get("type") || "all").toLowerCase();
  const genreParam = (url.searchParams.get("genre") || "").trim();
  const qParam = (url.searchParams.get("q") || "").trim().toLowerCase();

  const items = [];

  if (typeParam === "all" || typeParam === "movie") {
    const moviesRes = await env.DB.prepare(
      `SELECT * FROM movies WHERE status = 'published' ORDER BY release_year DESC, rating DESC`
    ).all();
    for (const row of (moviesRes && moviesRes.results) || []) {
      items.push(mapMovieRow(row));
    }
  }

  if (typeParam === "all" || typeParam === "series") {
    const seriesRes = await env.DB.prepare(
      `SELECT * FROM series WHERE status = 'published' ORDER BY release_year DESC, rating DESC`
    ).all();
    for (const row of (seriesRes && seriesRes.results) || []) {
      const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, row.id);
      items.push(mapSeriesRow(row, seasons));
    }
  }

  const filtered = items.filter((item) => {
    if (genreParam && genreParam.toLowerCase() !== "all") {
      const hasGenre = (item.genres || []).some(
        (g) => String(g).toLowerCase() === genreParam.toLowerCase()
      );
      if (!hasGenre) return false;
    }

    if (qParam) {
      const text = [
        item.title,
        item.originalTitle,
        item.synopsis,
        ...(item.genres || []),
        ...(item.languages || [])
      ]
        .join(" ")
        .toLowerCase();
      if (!text.includes(qParam)) return false;
    }

    return true;
  });

  return jsonSuccess(
    { items: filtered },
    200,
    { total: filtered.length }
  );
}

export async function handleGetCatalogItem(env, idOrSlug) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const key = String(idOrSlug || "").trim();
  if (!key) {
    return jsonError("INVALID_ID", "Content id or slug is required", 400);
  }

  const movieRow = await env.DB.prepare(
    `SELECT * FROM movies WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (movieRow) {
    return jsonSuccess({ item: mapMovieRow(movieRow) }, 200);
  }

  const seriesRow = await env.DB.prepare(
    `SELECT * FROM series WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (seriesRow) {
    const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, seriesRow.id);
    return jsonSuccess({ item: mapSeriesRow(seriesRow, seasons) }, 200);
  }

  return jsonError("CONTENT_NOT_FOUND", "Published movie or series not found", 404);
}

export async function handleGetSeriesSeasons(env, seriesIdOrSlug) {
  if (!env || !env.DB) {
    return jsonError("DB_NOT_CONFIGURED", "D1 database binding (DB) is not configured", 500);
  }

  const key = String(seriesIdOrSlug || "").trim();
  const seriesRow = await env.DB.prepare(
    `SELECT id, title FROM series WHERE (id = ?1 OR slug = ?1) AND status = 'published' LIMIT 1`
  )
    .bind(key)
    .first();

  if (!seriesRow) {
    return jsonError("SERIES_NOT_FOUND", "Published series not found", 404);
  }

  const seasons = await loadSeriesSeasonsAndEpisodes(env.DB, seriesRow.id);
  return jsonSuccess({ seriesId: seriesRow.id, seasons }, 200, { count: seasons.length });
}
