.PHONY: setup run test pull-model docker-up docker-down clean e2e benchmark assets demo

MODEL ?= qwen2.5:3b

setup:
	bash scripts/setup.sh --model $(MODEL)

run:
	bash scripts/run.sh

test:
	.venv/bin/pytest -q
	(cd dashboard && npm run build)

pull-model:
	bash scripts/pull_model.sh $(MODEL)

docker-up:
	docker compose up --build -d
	docker exec cybergraphrag-ollama ollama pull $(MODEL) || true
	@echo "API http://localhost:8000/docs  Dashboard http://localhost:5173"

docker-down:
	docker compose down

clean:
	rm -rf .venv dashboard/node_modules dashboard/dist
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +

e2e:
	.venv/bin/python scripts/run_pipeline_e2e.py

benchmark:
	.venv/bin/python evaluation/run_benchmark.py

assets: benchmark
	.venv/bin/python scripts/generate_report_assets.py

demo:
	.venv/bin/python scripts/demo.py --pause
