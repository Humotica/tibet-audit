-- ============================================
-- TIBET-AUDIT: NEDERLAND RIJKS INZICHT
-- Run in: https://console.cloud.google.com/bigquery
-- Dataset: bigquery-public-data.pypi.file_downloads
-- ============================================

-- Query 1: Downloads per LAND (laatste 35 dagen)
SELECT
  country_code,
  COUNT(*) as downloads,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 35 DAY)
GROUP BY country_code
ORDER BY downloads DESC
LIMIT 20;

-- ============================================

-- Query 2: NEDERLAND downloads per dag
SELECT
  DATE(timestamp) as datum,
  COUNT(*) as nl_downloads
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND country_code = 'NL'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 35 DAY)
GROUP BY datum
ORDER BY datum DESC;

-- ============================================

-- Query 3: Downloads per UUR vandaag (spike detectie)
SELECT
  TIMESTAMP_TRUNC(timestamp, HOUR) as uur,
  country_code,
  COUNT(*) as downloads
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND DATE(timestamp) = CURRENT_DATE()
GROUP BY uur, country_code
ORDER BY uur DESC, downloads DESC;

-- ============================================

-- Query 4: Python versies in NL (modern stack check)
SELECT
  details.python as python_version,
  COUNT(*) as downloads
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND country_code = 'NL'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 35 DAY)
GROUP BY python_version
ORDER BY downloads DESC
LIMIT 10;

-- ============================================

-- Query 5: Installer types in NL (pip, uv, poetry, etc)
SELECT
  details.installer.name as installer,
  COUNT(*) as downloads
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND country_code = 'NL'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 35 DAY)
GROUP BY installer
ORDER BY downloads DESC;

-- ============================================

-- Query 6: VERGELIJK met andere compliance tools
SELECT
  file.project as package,
  COUNT(*) as downloads_35d
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project IN ('tibet-audit', 'checkov', 'prowler', 'scoutsuite')
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 35 DAY)
GROUP BY package
ORDER BY downloads_35d DESC;

-- ============================================

-- Query 7: FLEUR SPIKE CHECK - Downloads laatste 6 uur
SELECT
  TIMESTAMP_TRUNC(timestamp, HOUR) as uur,
  country_code,
  details.installer.name as installer,
  COUNT(*) as downloads
FROM `bigquery-public-data.pypi.file_downloads`
WHERE file.project = 'tibet-audit'
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 6 HOUR)
GROUP BY uur, country_code, installer
ORDER BY uur DESC;
