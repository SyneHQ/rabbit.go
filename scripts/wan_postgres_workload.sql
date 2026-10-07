-- Synthetic ride-hailing workload used in the Rabbit/PostgreSQL WAN benchmark.
-- Use a newly created dedicated database named rabbit_wan_<suffix>.
-- Initial load: psql "$FIXTURE_ADMIN_DSN" -v stage_rows=1000000 -f this-file.sql
-- Expansion:   same command with stage_rows=3000000; existing rows are preserved.
-- Fact rows: stage_rows trips plus floor(stage_rows/10) adjustments.
-- Six tables total. No user data, extensions, COPY exports or server changes.
-- Optional reader grant: pass -v reader_role=<dedicated-existing-read-only-role>.
-- Workloads below run only with -v run_workloads=true; the loader skips them.
\set ON_ERROR_STOP on
\if :{?stage_rows}
\else
\set stage_rows 1000000
\endif
SELECT set_config('rabbit_wan.stage_rows', :'stage_rows', false);
DO $$ BEGIN
 IF current_database() !~ '^rabbit_wan_[a-z0-9_]+$' THEN
  RAISE EXCEPTION 'Use a fresh dedicated rabbit_wan_<suffix> database';
 END IF;
 IF current_setting('rabbit_wan.stage_rows')::BIGINT NOT IN (1000000,3000000) THEN
  RAISE EXCEPTION 'stage_rows must be 1000000 or 3000000';
 END IF;
END $$;
SET statement_timeout='15min';
SET lock_timeout='5s';
SET work_mem='8MB';
SET maintenance_work_mem='64MB';
SET max_parallel_workers_per_gather=1;
SET max_parallel_maintenance_workers=2;
SET TIME ZONE 'UTC';
BEGIN;
CREATE SCHEMA IF NOT EXISTS rabbit_wan;
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.zones (
 zone_id SMALLINT PRIMARY KEY,
 zone_name TEXT NOT NULL,
 borough SMALLINT NOT NULL CHECK(borough BETWEEN 1 AND 8)
);
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.services (
 service_id SMALLINT PRIMARY KEY,
 service_name TEXT NOT NULL,
 minimum_fare_cents INTEGER NOT NULL CHECK(minimum_fare_cents>0)
);
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.riders (
 rider_id INTEGER PRIMARY KEY,
 home_zone_id SMALLINT NOT NULL REFERENCES rabbit_wan.zones(zone_id),
 cohort SMALLINT NOT NULL CHECK(cohort BETWEEN 1 AND 4),
 joined_on DATE NOT NULL
);
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.drivers (
 driver_id INTEGER PRIMARY KEY,
 home_zone_id SMALLINT NOT NULL REFERENCES rabbit_wan.zones(zone_id),
 tier SMALLINT NOT NULL CHECK(tier BETWEEN 1 AND 3),
 onboarded_on DATE NOT NULL
);
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.trips (
 trip_id BIGINT PRIMARY KEY,
 requested_at TIMESTAMPTZ NOT NULL,
 rider_id INTEGER NOT NULL REFERENCES rabbit_wan.riders(rider_id),
 driver_id INTEGER NOT NULL REFERENCES rabbit_wan.drivers(driver_id),
 fare_cents INTEGER NOT NULL CHECK(fare_cents BETWEEN 250 AND 10000),
 duration_seconds INTEGER NOT NULL CHECK(duration_seconds BETWEEN 60 AND 3600),
 distance_m INTEGER NOT NULL CHECK(distance_m BETWEEN 300 AND 25000),
 pickup_zone_id SMALLINT NOT NULL REFERENCES rabbit_wan.zones(zone_id),
 dropoff_zone_id SMALLINT NOT NULL REFERENCES rabbit_wan.zones(zone_id),
 service_id SMALLINT NOT NULL REFERENCES rabbit_wan.services(service_id),
 status SMALLINT NOT NULL CHECK(status IN (0,1,2))
 -- 0=completed, 1=cancelled, 2=no-show. Money remains integer cents.
);
CREATE UNLOGGED TABLE IF NOT EXISTS rabbit_wan.adjustments (
 trip_id BIGINT PRIMARY KEY REFERENCES rabbit_wan.trips(trip_id),
 amount_cents INTEGER NOT NULL CHECK(amount_cents BETWEEN -175 AND -25),
 reason_code SMALLINT NOT NULL CHECK(reason_code BETWEEN 1 AND 3),
 memo TEXT
);
INSERT INTO rabbit_wan.zones
 SELECT i::SMALLINT,'Zone '||LPAD(i::TEXT,2,'0'),((i-1)/8+1)::SMALLINT
 FROM generate_series(1,64) s(i) ON CONFLICT DO NOTHING;
INSERT INTO rabbit_wan.services VALUES
 (1,'Basic',250),(2,'Comfort',400),(3,'XL',600),(4,'Priority',800)
 ON CONFLICT DO NOTHING;
INSERT INTO rabbit_wan.riders
 SELECT i,((i*7)%64+1)::SMALLINT,(i%4+1)::SMALLINT,DATE '2024-01-01'+i%730
 FROM generate_series(1,10000) s(i) ON CONFLICT DO NOTHING;
INSERT INTO rabbit_wan.drivers
 SELECT i,((i*11)%64+1)::SMALLINT,(i%3+1)::SMALLINT,DATE '2023-01-01'+i%1095
 FROM generate_series(1,2048) s(i) ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT COALESCE(MAX(trip_id),0) FROM rabbit_wan.trips)>current_setting('rabbit_wan.stage_rows')::BIGINT THEN
  RAISE EXCEPTION 'Refusing to shrink an existing stage';
 END IF;
END $$;
INSERT INTO rabbit_wan.trips
 SELECT i,TIMESTAMPTZ '2026-01-01 00:00:00+00'+((i-1)%2592000)*INTERVAL '1 second',
 ((i*48271%2147483647)%10000+1)::INTEGER,
 ((i*69621%2147483647)%2048+1)::INTEGER,
 (250+i*19%9751)::INTEGER,(60+i*53%3541)::INTEGER,(300+i*43%24701)::INTEGER,
 ((i*29+i/11)%64+1)::SMALLINT,((i*31+i/13)%64+1)::SMALLINT,
 ((i*17+i/97)%4+1)::SMALLINT,
 CASE WHEN i%23=0 THEN 2 WHEN i%11=0 THEN 1 ELSE 0 END::SMALLINT
 FROM generate_series(
  (SELECT COALESCE(MAX(trip_id),0)+1 FROM rabbit_wan.trips),
  current_setting('rabbit_wan.stage_rows')::BIGINT
 ) s(i);
INSERT INTO rabbit_wan.adjustments
 SELECT i,-((i%7+1)*25)::INTEGER,(i/10%3+1)::SMALLINT,
 CASE WHEN i%30=0 THEN NULL ELSE 'adjustment-'||(i/10%3+1)::TEXT END
 FROM generate_series(10,current_setting('rabbit_wan.stage_rows')::BIGINT,10) s(i)
 ON CONFLICT DO NOTHING;
CREATE INDEX IF NOT EXISTS trips_driver_requested_idx
 ON rabbit_wan.trips(driver_id,requested_at);
CREATE INDEX IF NOT EXISTS trips_requested_brin
 ON rabbit_wan.trips USING BRIN(requested_at) WITH(pages_per_range=64);
DO $$ BEGIN
 IF (SELECT COUNT(*) FROM rabbit_wan.trips)<>current_setting('rabbit_wan.stage_rows')::BIGINT
 OR (SELECT COUNT(*) FROM rabbit_wan.adjustments)<>current_setting('rabbit_wan.stage_rows')::BIGINT/10
 OR (SELECT COUNT(*) FROM rabbit_wan.riders)<>10000
 OR (SELECT COUNT(*) FROM rabbit_wan.drivers)<>2048
 OR (SELECT COUNT(*) FROM rabbit_wan.zones)<>64
 OR (SELECT COUNT(*) FROM rabbit_wan.services)<>4 THEN
  RAISE EXCEPTION 'Fixture row counts disagree with the requested stage';
 END IF;
END $$;
\if :{?reader_role}
GRANT USAGE ON SCHEMA rabbit_wan TO :"reader_role";
GRANT SELECT ON ALL TABLES IN SCHEMA rabbit_wan TO :"reader_role";
\endif
COMMIT;
ANALYZE rabbit_wan.zones;
ANALYZE rabbit_wan.services;
ANALYZE rabbit_wan.riders;
ANALYZE rabbit_wan.drivers;
ANALYZE rabbit_wan.trips;
ANALYZE rabbit_wan.adjustments;
-- Measure after 1M; expand only after checking actual disk and CPU/memory headroom.
SELECT relname,pg_total_relation_size(c.oid) AS total_bytes
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rabbit_wan' AND c.relkind='r' ORDER BY relname;
SELECT COUNT(*) AS trips,COUNT(*) FILTER(WHERE status=0) AS completed,
 COUNT(*) FILTER(WHERE status=1) AS cancelled,COUNT(*) FILTER(WHERE status=2) AS no_show,
 SUM(fare_cents)::BIGINT AS fare_cents FROM rabbit_wan.trips;

\if :{?run_workloads}
\if :run_workloads

-- BEGIN QUERY daily_zone_service
WITH enriched AS (
 SELECT t.requested_at::DATE AS day,z.borough,s.service_id,s.service_name,
 t.status,t.fare_cents,t.duration_seconds,r.cohort,d.tier,COALESCE(a.amount_cents,0) AS adjustment
 FROM rabbit_wan.trips t JOIN rabbit_wan.zones z ON z.zone_id=t.pickup_zone_id
 JOIN rabbit_wan.services s ON s.service_id=t.service_id
 JOIN rabbit_wan.riders r ON r.rider_id=t.rider_id
 JOIN rabbit_wan.drivers d ON d.driver_id=t.driver_id
 LEFT JOIN rabbit_wan.adjustments a ON a.trip_id=t.trip_id
), daily AS (
 SELECT day,borough,service_id,service_name,
 COUNT(*) FILTER(WHERE status=0)::BIGINT AS completed,
 COUNT(*) FILTER(WHERE status=1)::BIGINT AS cancelled,
 COUNT(*) FILTER(WHERE status=2)::BIGINT AS no_show,
 COUNT(*) FILTER(WHERE status=0 AND cohort=4)::BIGINT AS enterprise_completed,
 COUNT(*) FILTER(WHERE status=0 AND tier=3)::BIGINT AS tier3_completed,
 SUM(CASE WHEN status=0 THEN fare_cents+adjustment ELSE 0 END)::BIGINT AS net_cents,
 CAST(ROUND(AVG(duration_seconds) FILTER(WHERE status=0),2) AS NUMERIC(18,2)) AS avg_duration
 FROM enriched GROUP BY day,borough,service_id,service_name
), ranked AS (
 SELECT *,ROW_NUMBER() OVER(PARTITION BY day ORDER BY net_cents DESC,borough,service_id)::BIGINT AS demand_rank
 FROM daily
)
SELECT * FROM ranked WHERE demand_rank<=5 ORDER BY day,demand_rank;
-- END QUERY daily_zone_service

-- BEGIN QUERY driver_leaderboard
WITH driver_totals AS (
 SELECT d.driver_id,d.tier,z.borough,COUNT(*)::BIGINT AS completed,
 COUNT(*) FILTER(WHERE r.cohort=4)::BIGINT AS enterprise_completed,
 COUNT(*) FILTER(WHERE s.service_id=4)::BIGINT AS priority_completed,
 SUM(t.fare_cents+COALESCE(a.amount_cents,0))::BIGINT AS net_cents,
 SUM(t.distance_m)::BIGINT AS distance_m
 FROM rabbit_wan.trips t JOIN rabbit_wan.drivers d ON d.driver_id=t.driver_id
 JOIN rabbit_wan.zones z ON z.zone_id=d.home_zone_id
 JOIN rabbit_wan.riders r ON r.rider_id=t.rider_id
 JOIN rabbit_wan.services s ON s.service_id=t.service_id
 LEFT JOIN rabbit_wan.adjustments a ON a.trip_id=t.trip_id
 WHERE t.status=0 AND t.requested_at<TIMESTAMPTZ '2026-01-08 00:00:00+00'
 GROUP BY d.driver_id,d.tier,z.borough
), ranked AS (
 SELECT *,ROW_NUMBER() OVER(PARTITION BY borough ORDER BY net_cents DESC,driver_id)::BIGINT AS driver_rank
 FROM driver_totals
)
SELECT * FROM ranked WHERE driver_rank<=3 ORDER BY borough,driver_rank;
-- END QUERY driver_leaderboard

-- BEGIN QUERY weekly_cohort
WITH rider_activity AS (
 SELECT r.cohort,z.borough,((t.requested_at::DATE-DATE '2026-01-01')/7)::INTEGER AS week,r.rider_id,
 COUNT(*)::BIGINT AS trips,SUM(t.fare_cents+COALESCE(a.amount_cents,0))::BIGINT AS net_cents,
 COUNT(*) FILTER(WHERE s.service_id=4)::BIGINT AS priority_trips,
 COUNT(*) FILTER(WHERE d.tier=3)::BIGINT AS tier3_trips
 FROM rabbit_wan.trips t JOIN rabbit_wan.riders r ON r.rider_id=t.rider_id
 JOIN rabbit_wan.zones z ON z.zone_id=t.pickup_zone_id
 JOIN rabbit_wan.drivers d ON d.driver_id=t.driver_id
 JOIN rabbit_wan.services s ON s.service_id=t.service_id
 LEFT JOIN rabbit_wan.adjustments a ON a.trip_id=t.trip_id
 WHERE t.status=0 GROUP BY r.cohort,z.borough,week,r.rider_id
), weekly AS (
 SELECT cohort,borough,week,COUNT(*)::BIGINT AS active_riders,SUM(trips)::BIGINT AS trips,
 SUM(net_cents)::BIGINT AS net_cents,SUM(priority_trips)::BIGINT AS priority_trips,SUM(tier3_trips)::BIGINT AS tier3_trips
 FROM rider_activity GROUP BY cohort,borough,week
), compared AS (
 SELECT *,LAG(active_riders) OVER(PARTITION BY cohort,borough ORDER BY week)::BIGINT AS previous_active_riders
 FROM weekly
)
SELECT *,CAST(ROUND((active_riders-previous_active_riders)::NUMERIC*100/NULLIF(previous_active_riders,0),2) AS NUMERIC(18,2)) AS growth_pct
 FROM compared ORDER BY cohort,borough,week;
-- END QUERY weekly_cohort

-- BEGIN QUERY adjustment_reconciliation
WITH credits AS (
 SELECT z.borough,s.service_id,a.reason_code,COUNT(*)::BIGINT AS adjustments,
 COUNT(*) FILTER(WHERE a.memo IS NULL)::BIGINT AS null_memos,
 COUNT(*) FILTER(WHERE t.status<>0)::BIGINT AS non_completed,
 COUNT(*) FILTER(WHERE r.cohort=4)::BIGINT AS enterprise_adjustments,
 COUNT(*) FILTER(WHERE d.tier=3)::BIGINT AS tier3_adjustments,
 SUM(-a.amount_cents)::BIGINT AS credit_cents,
 SUM(CASE WHEN t.status=0 THEN t.fare_cents+a.amount_cents ELSE 0 END)::BIGINT AS completed_net_cents
 FROM rabbit_wan.adjustments a JOIN rabbit_wan.trips t ON t.trip_id=a.trip_id
 JOIN rabbit_wan.zones z ON z.zone_id=t.pickup_zone_id
 JOIN rabbit_wan.services s ON s.service_id=t.service_id
 JOIN rabbit_wan.riders r ON r.rider_id=t.rider_id
 JOIN rabbit_wan.drivers d ON d.driver_id=t.driver_id
 GROUP BY z.borough,s.service_id,a.reason_code
)
SELECT *,SUM(credit_cents) OVER(PARTITION BY borough,service_id ORDER BY reason_code ROWS UNBOUNDED PRECEDING)::BIGINT AS cumulative_credit_cents
 FROM credits ORDER BY borough,service_id,reason_code;
-- END QUERY adjustment_reconciliation

-- BEGIN QUERY route_mix
WITH routes AS (
 SELECT p.borough AS origin_borough,z.borough AS destination_borough,s.service_id,COUNT(*)::BIGINT AS completed,
 COUNT(*) FILTER(WHERE r.cohort=4)::BIGINT AS enterprise_completed,
 COUNT(*) FILTER(WHERE d.tier=3)::BIGINT AS tier3_completed,
 SUM(t.distance_m)::BIGINT AS distance_m,SUM(t.fare_cents+COALESCE(a.amount_cents,0))::BIGINT AS net_cents
 FROM rabbit_wan.trips t JOIN rabbit_wan.zones p ON p.zone_id=t.pickup_zone_id
 JOIN rabbit_wan.zones z ON z.zone_id=t.dropoff_zone_id
 JOIN rabbit_wan.services s ON s.service_id=t.service_id
 JOIN rabbit_wan.riders r ON r.rider_id=t.rider_id
 JOIN rabbit_wan.drivers d ON d.driver_id=t.driver_id
 LEFT JOIN rabbit_wan.adjustments a ON a.trip_id=t.trip_id
 WHERE t.status=0 GROUP BY p.borough,z.borough,s.service_id
), ranked AS (
 SELECT *,CAST(ROUND(completed::NUMERIC*100/SUM(completed) OVER(PARTITION BY origin_borough),2) AS NUMERIC(18,2)) AS share_pct,
 ROW_NUMBER() OVER(PARTITION BY origin_borough ORDER BY completed DESC,destination_borough,service_id)::BIGINT AS route_rank
 FROM routes
)
SELECT * FROM ranked WHERE route_rank<=5 ORDER BY origin_borough,route_rank;
-- END QUERY route_mix

-- BEGIN QUERY raw_trips
SELECT t.trip_id,t.requested_at,t.rider_id,t.driver_id,t.pickup_zone_id,t.dropoff_zone_id,t.service_id,t.status,
 t.fare_cents,t.duration_seconds,t.distance_m,a.amount_cents AS adjustment_cents,a.memo
 FROM rabbit_wan.trips t LEFT JOIN rabbit_wan.adjustments a ON a.trip_id=t.trip_id ORDER BY t.trip_id;
-- END QUERY raw_trips

\endif
\endif
