@echo off
setlocal

IF "%1"=="" GOTO help
IF "%1"=="setup" GOTO setup
IF "%1"=="start" GOTO start
IF "%1"=="stop" GOTO stop
IF "%1"=="restart" GOTO restart
IF "%1"=="reset" GOTO reset
IF "%1"=="health" GOTO health
IF "%1"=="logs" GOTO logs
IF "%1"=="logs-redis" GOTO logs-redis
IF "%1"=="logs-db" GOTO logs-db
IF "%1"=="ps" GOTO ps
IF "%1"=="shell-redis" GOTO shell-redis
IF "%1"=="shell-db" GOTO shell-db
IF "%1"=="clean" GOTO clean
IF "%1"=="help" GOTO help
IF "%1"=="generate-pcap" GOTO generate-pcap
IF "%1"=="analyze-pcap" GOTO analyze-pcap
IF "%1"=="pcap-info" GOTO pcap-info

:setup
echo Running setup...
bash scripts/setup.sh
GOTO end

:start
echo Starting services...
docker compose up -d
GOTO end

:stop
echo Stopping services...
docker compose down
GOTO end

:restart
echo Restarting services...
docker compose down
docker compose up -d
GOTO end

:reset
echo Resetting environment...
bash scripts/reset.sh
GOTO end

:health
echo Running health check...
bash scripts/health_check.sh
GOTO end

:logs
docker compose logs -f
GOTO end

:logs-redis
docker compose logs -f redis
GOTO end

:logs-db
docker compose logs -f database
GOTO end

:ps
docker compose ps
GOTO end

:shell-redis
docker exec -it securisphere-redis redis-cli
GOTO end

:shell-db
docker exec -it securisphere-db psql -U securisphere_user -d securisphere_db
GOTO end

:clean
echo Cleaning up...
del /s /q *.pyc
rmdir /s /q __pycache__
del /s /q logs\*.log
GOTO end

:generate-pcap
echo Generating sample PCAP files...
pushd simulation
python generate_sample_pcap.py all --output-dir ../samples/pcap
popd
GOTO end

:analyze-pcap
IF "%2"=="" (
    echo Usage: run.bat analyze-pcap [path_to_pcap]
    GOTO end
)
echo Analyzing %2...
pushd monitors\network
set REDIS_HOST=localhost
python pcap_analyzer.py "../../%2" --speed 0
popd
GOTO end

:pcap-info
IF "%2"=="" (
    echo Usage: run.bat pcap-info [path_to_pcap]
    GOTO end
)
pushd monitors\network
python pcap_analyzer.py "../../%2" --info-only
popd
GOTO end

:help
echo Available commands:
echo   setup       - Run initial setup script
echo   start       - Start services
echo   stop        - Stop services
echo   restart     - Restart services
echo   reset       - Reset environment
echo   health      - Run health check
echo   logs        - View all logs
echo   logs-redis  - View redis logs
echo   logs-db     - View database logs
echo   ps          - List running containers
echo   shell-redis - Open redis-cli
echo   shell-db    - Open psql shell
echo   clean       - Remove temporary files
echo   generate-pcap - Generate sample PCAP files
echo   analyze-pcap  - Analyze PCAP file (requires arg)
echo   pcap-info     - Show PCAP file info (requires arg)
GOTO end

:end
endlocal
