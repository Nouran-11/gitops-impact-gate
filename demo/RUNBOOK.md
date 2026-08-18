# Live demo runbook

Follow this in order, copy-paste only, from the repository root (the directory that contains `pyproject.toml` and `demo/`). Do not improvise. The controller terminal is sacred: if you type in it you will kill the demo.

What this proves, in one sentence each:

1. **PR gate (selector-break):** file-by-file linters accept a label rename; the graph finds `Service/checkout` matching zero pods and the path `Ingress → Service → (no pods)`.
2. **Bad image:** a closed `Action` enum selects **rollback** for `ErrImagePull` / `ImagePullBackOff`.
3. **Real bug (the important one):** the same CrashLoopBackOff path selects **escalate** — the system knows when not to act.

Policy stays `mode: dry-run`. You are proving classification. After debounce the controller logs `dry-run: would rollback` or `dry-run: would escalate`. Do not patch the policy to `enforce` on stage: a real rollback also requires a ReplicaSet that has been fully Ready for ≥10 minutes, and you do not have that time.

---

## Pre-flight (the night before)

Do this on the demo laptop. Do not leave it until every check below is green.

### Install

macOS (Homebrew):

```bash
brew install python@3.12 kind kubectl pipx ollama
brew install kube-linter
pipx ensurepath
pipx install checkov
```

Ubuntu / Debian (Docker must already be running):

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev ca-certificates curl
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  KIND_URL=https://kind.sigs.k8s.io/dl/v0.32.0/kind-linux-amd64
           KUBECTL_ARCH=amd64
           LINTER_URL=https://github.com/stackrox/kube-linter/releases/download/v0.8.3/kube-linter-linux.tar.gz ;;
  aarch64) KIND_URL=https://kind.sigs.k8s.io/dl/v0.32.0/kind-linux-arm64
           KUBECTL_ARCH=arm64
           LINTER_URL=https://github.com/stackrox/kube-linter/releases/download/v0.8.3/kube-linter-linux_arm64.tar.gz ;;
  *) echo "unsupported arch: $ARCH"; exit 1 ;;
esac
curl -Lo ./kind "$KIND_URL"
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${KUBECTL_ARCH}/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/kubectl
python3.12 -m pip install --user pipx
python3.12 -m pipx ensurepath
export PATH="$HOME/.local/bin:$PATH"
pipx install checkov
curl -L -o /tmp/kube-linter.tar.gz "$LINTER_URL"
tar -xzf /tmp/kube-linter.tar.gz -C /tmp
sudo mv /tmp/kube-linter /usr/local/bin/kube-linter
curl -fsSL https://ollama.com/install.sh | sh
```

**Checkov via pipx, never `pip install checkov` into the project venv.** Checkov’s dependency set fights with ours. `pipx` keeps it on `PATH` in its own environment.

### Project venv

```bash
cd "$(git rev-parse --show-toplevel)"
git checkout main
git pull
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e ".[dev]"
```

Every later terminal that runs `impactgate`, `kopf`, `pytest`, `ruff`, or `mypy` must have this venv activated.

### Ollama model

Default model in code is `llama3.1:8b`. Pull it once; it is several gigabytes.

```bash
ollama serve
```

Leave that running, then in another terminal:

```bash
ollama pull llama3.1:8b
ollama run llama3.1:8b "Reply with the single word pong."
```

You want a one-word reply, then `/bye`. If pull or run fails, Demo 1 still works with `IMPACTGATE_LLM_PROVIDER=fake` (canned prose, same graph headings).

### Kind cluster and image warm-up

```bash
source .venv/bin/activate
kind create cluster --config demo/kind-config.yaml
kubectl config use-context kind-impactgate
kubectl get nodes
kubectl apply -f deploy/crd.yaml
kubectl get ns demo >/dev/null 2>&1 || kubectl create namespace demo
kubectl apply -f deploy/policy.yaml
kubectl apply -f demo/manifests/bad-image/deployment.yaml
kubectl -n demo rollout status deployment/storefront --timeout=120s
kubectl -n demo delete deployment storefront
```

`rollout status` succeeding means `nginx:1.25` is cached in the node. Demo 2’s bad tag must **not** be pulled in advance.

### Verify binaries

```bash
source .venv/bin/activate
python --version
# Python 3.12.x
docker info >/dev/null && echo docker_ok
kind version
kubectl version --client
checkov --version
kube-linter version
kopf --help >/dev/null && echo kopf_ok
impactgate --help
ollama list
# must include llama3.1:8b
```

### Five-minute smoke test

Run this the night before **and** once on the morning of, before anyone sits down. All of it should finish in about five minutes on a warm cluster.

```bash
source .venv/bin/activate
cd "$(git rev-parse --show-toplevel)"
export IMPACTGATE_LLM_PROVIDER=fake

python --version
# expect: Python 3.12.x

pytest -q
# expect: N passed, 0 failed (currently 155 passed in ~7s)

ruff check src tests
# expect: All checks passed!

mypy
# expect: Success: no issues found in 40 source files

IMPACTGATE_LLM_PROVIDER=fake impactgate analyze demo/manifests/selector-break --no-cache
# expect:
#   **Risk:** low
#   no findings

kubectl config use-context kind-impactgate
kubectl get nodes
# expect: one node Ready

kubectl get crd remediationpolicies.impactgate.io
# expect: NAME ... CREATED AT

kubectl -n demo get remediationpolicy default -o yaml
# expect: spec.mode: dry-run

python -c "import impactgate.controller.watcher as w; print(w.__file__)"
# expect: a path under this repo (…/src/impactgate/controller/watcher.py)

curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:11434/api/tags
# expect: 200  (ollama). If this is not 200, Demo 1 uses fake (already exported above).
```

If pytest is not green, stop. Do not demo a dirty tree.

---

## Setup (day of, before the room fills)

Activate the venv in **every** terminal you will use:

```bash
cd "$(git rev-parse --show-toplevel)"
source .venv/bin/activate
kubectl config use-context kind-impactgate
```

### 1. Cluster

```bash
kubectl get nodes
```

Expected: one node, `Ready`. If `kind get clusters` does not list `impactgate`:

```bash
kind create cluster --config demo/kind-config.yaml
kubectl config use-context kind-impactgate
```

That create takes about a minute.

### 2. CRD first, then namespace, then policy

Two files, two applies, CRD first. A combined apply is rejected on a fresh cluster because the `RemediationPolicy` instance is validated before the CRD exists.

```bash
kubectl apply -f deploy/crd.yaml
```

Expected:

```text
customresourcedefinition.apiextensions.k8s.io/remediationpolicies.impactgate.io created
```

or `configured` if you already applied it last night.

```bash
kubectl get ns demo >/dev/null 2>&1 || kubectl create namespace demo
```

Expected: `namespace/demo created`, or no output if it already exists.

```bash
kubectl apply -f deploy/policy.yaml
```

Expected:

```text
remediationpolicy.impactgate.io/default created
```

or `configured`. Confirm:

```bash
kubectl -n demo get remediationpolicy default -o jsonpath='{.spec.mode} {.spec.allowedActions}{"\n"}'
```

Expected:

```text
dry-run ["rollback","restart"]
```

Do not patch this to `enforce`.

### 3. Confirm the label that the gate actually reads

The controller reads **pod** labels. Kubernetes copies `spec.template.metadata.labels` onto pods. A label on `metadata.labels` of the Deployment is ignored and you will only see `skipping unmanaged pod`.

The shipped demos already have this on the pod template:

```text
impactgate.io/managed: "true"
```

Sanity check before you start the controller:

```bash
grep -n 'impactgate.io/managed' demo/manifests/bad-image/deployment.yaml demo/manifests/real-bug/deployment.yaml demo/manifests/selector-break/deployment.yaml
```

Expected: each hit is under `template:` / `labels:`, not under the Deployment’s own `metadata:`.

---

## Terminal layout

Open four terminals. Activate the venv in 1, 3, and 4. Set the kubectl context in 2, 3, and 4.

| Terminal | Title | What runs | Type in it? |
|---|---|---|---|
| **1** | `CONTROLLER` | `kopf run` | **Never.** One accidental Ctrl-C ends Demos 2 and 3. |
| **2** | `PODS` | `kubectl -n demo get pods -w` | Do not type. Watch phases and reasons. |
| **3** | `OPS` | Every command in this runbook | Yes. This is the only working terminal. |
| **4** | `METRICS` | `curl` when asked | Only the curl. Keep the output on screen. |

Start Terminal 1 **after** Setup (CRD + policy), **before** Demo 2. Demo 1 does not need it.

### Start the controller (Terminal 1)

This is the command that actually watches pods:

```bash
source .venv/bin/activate
cd "$(git rev-parse --show-toplevel)"
IMPACTGATE_CONTROLLER_ENABLED=true kopf run -m impactgate.controller.watcher --namespace demo --verbose
```

Expected within a few seconds (kopf timestamps vary; the payload must appear):

```text
serving /metrics on port 8000
```

and, because the policy already exists:

```text
loaded RemediationPolicy demo/default mode=dry-run allowed=['rollback', 'restart']
```

Leave this terminal alone.

`impactgate controller` starts the metrics server and does **not** watch pods. A CrashLoopBackOff will produce no controller output. Do not use it.

If kopf complains about peering / another operator, rerun the same command with `--standalone` appended. Do not switch to `impactgate controller`.

### Start the pod watch (Terminal 2)

```bash
kubectl config use-context kind-impactgate
kubectl -n demo get pods -w
```

Empty is fine until Demo 2.

---

## Demo 1 — the PR gate (selector-break)

**Claim:** Checkov and kube-linter look at one file. They cannot see that renaming a pod label leaves `Service/checkout` selecting nothing while `Ingress/public` still routes to that Service.

**Duration:** about 2 minutes if Ollama answers; about 15 seconds with `fake`.

Work only on copies. Do not edit `demo/manifests/selector-break` in git.

### 1. Copy the clean tree, then break the working copy

```bash
source .venv/bin/activate
cd "$(git rev-parse --show-toplevel)"
rm -rf /tmp/ig-before /tmp/ig-after
cp -a demo/manifests/selector-break /tmp/ig-before
cp -a demo/manifests/selector-break /tmp/ig-after
python3 - <<'PY'
from pathlib import Path
p = Path("/tmp/ig-after/deployment.yaml")
text = p.read_text()
needle = """  template:
    metadata:
      labels:
        app: checkout
"""
repl = """  template:
    metadata:
      labels:
        app: checkout-v2
"""
if needle not in text:
    raise SystemExit("template labels not found — stop, do not continue")
p.write_text(text.replace(needle, repl, 1))
print("relabeled template app: checkout -> checkout-v2")
PY
```

Expected: `relabeled template app: checkout -> checkout-v2`.

Confirm you did **not** change `spec.selector.matchLabels` (that must stay `checkout`):

```bash
grep -n 'app:' /tmp/ig-after/deployment.yaml
```

Expected:

```text
      app: checkout
        app: checkout-v2
```

First line is `matchLabels`. Second is the pod template. If both say `checkout-v2`, you edited the wrong place — reset (below) and redo.

Do not `git apply demo/manifests/selector-break/broken.patch`. That hunk predates the managed-label line and fails.

### 2. File-by-file linters on the broken directory

```bash
checkov -d /tmp/ig-after --framework kubernetes --compact
kube-linter lint /tmp/ig-after
```

**What to say, even if the exit code is 1:** these tools may complain about CPU limits, memory limits, or security context. That is expected on these manifests. Scroll the output: there is no finding that `Service/checkout` now matches zero pods, and no mention of `checkout-v2` breaking a selector. That is the gap.

### 3. Analyze before/after

```bash
export IMPACTGATE_LLM_PROVIDER=ollama
export IMPACTGATE_OLLAMA_MODEL=llama3.1:8b
impactgate analyze /tmp/ig-after --before /tmp/ig-before --no-cache
```

If Ollama has not produced a heading after ~20 seconds of silence, Ctrl-C and rerun with the backup provider (same graph, canned sentences):

```bash
IMPACTGATE_LLM_PROVIDER=fake impactgate analyze /tmp/ig-after --before /tmp/ig-before --no-cache
```

Do **not** leave `IMPACTGATE_LLM_PROVIDER` unset. The default is Gemini. With no API key it retries, then Groq, then Ollama, and the demo stalls.

### Expected output (key lines)

You must see all of these. Prose under the headings comes from the LLM and will not match word-for-word.

```text
**Risk:** high
```

```text
3 new finding(s): broken-selector, mismatching-selector, unreachable-workload
```

```text
### critical: `broken-selector`
```

The path in that finding (LLM text or the deterministic evidence) contains:

```text
demo/Ingress/public
demo/Service/checkout
(no pods)
```

Mermaid in the report:

```text
demo_Ingress_public["demo/Ingress/public"]
demo_Service_checkout["demo/Service/checkout"]
demo_Deployment_checkout["demo/Deployment/checkout"]
```

Deterministic evidence, if you need to quote it: `spec.selector app=checkout matches no workload`. Severity is **critical** because the reverse walk hits the Ingress (externally exposed). Checkov cannot produce that path.

If scanners are on `PATH`, a `## Scanner findings` section may appear under the relationship findings (CPU/security). Ignore it. Point at `## Relationship findings` and `broken-selector`.

Analyzing the clean copy must stay empty (this is why `--before` exists — we only report what the PR introduced):

```bash
IMPACTGATE_LLM_PROVIDER=fake impactgate analyze /tmp/ig-before --no-cache
```

Expected: `**Risk:** low` and `no findings`.

### Reset this demo

```bash
rm -rf /tmp/ig-before /tmp/ig-after
git checkout -- demo/manifests/selector-break
```

---

## Demo 2 — bad image → rollback

**Claim:** a missing image is classified as **rollback**, from a fixed enum, not from generated `kubectl`.

**Duration:** apply is seconds; then **one to two minutes of apparent silence** while debounce counts to 3 failures in a 5-minute window. That wait is the demo working. Do not restart the controller.

Terminal 1 must already be running `kopf run`. Terminal 2 must already be `get pods -w`.

### 1. Deploy the healthy storefront

```bash
kubectl apply -f demo/manifests/bad-image/deployment.yaml
kubectl -n demo rollout status deployment/storefront --timeout=120s
kubectl -n demo get deploy storefront -o jsonpath='{.spec.template.metadata.labels}{"\n"}'
kubectl -n demo get pods -l app=storefront --show-labels
```

Expected jsonpath:

```text
{"app":"storefront","impactgate.io/managed":"true"}
```

The pod `--show-labels` line **must** include `impactgate.io/managed=true`. If it does not, stop and fix the template labels; the controller will log `skipping unmanaged pod` and never decide.

Terminal 2: pod `Running` / `Ready`.

### 2. Break the image

```bash
kubectl -n demo set image deployment/storefront storefront=nginx:does-not-exist
```

Terminal 2 should move to `ErrImagePull` and then `ImagePullBackOff` (either reason is fine; both classify as rollback).

### 3. Wait. Do not type.

On Terminal 1 you should first see, more than once:

```text
debouncing demo/storefront after ErrImagePull
```

or the same line with `ImagePullBackOff`.

**Wait one to two minutes.** kubelet backoff is not instant. If you talk over this, say: “three failures in five minutes so a normal rollout cannot trigger us.”

Then the decision line (this is the slide):

```text
dry-run: would rollback on demo/storefront (reason=ErrImagePull, mode=dry-run, allowed=['rollback', 'restart'])
```

`reason=ImagePullBackOff` is the same win. `mode=dry-run` is expected. `allowed=[]` means the policy never loaded — see troubleshooting.

Leave storefront crashing only until you have pointed at that line, then delete it so Demo 3’s logs are unambiguous:

```bash
kubectl -n demo delete deployment storefront
```

---

## Demo 3 — real bug → escalate (most important)

**Claim:** a process that prints a traceback and exits is an application bug. The controller **escalates** (notify a human, do not rollback/restart). This is the demo that proves the system knows when not to act. A tool that remediates every crash is dangerous; this one refuses.

**Duration:** same as Demo 2 — apply, then **one to two minutes** for debounce.

### 1. Deploy healthy payments

```bash
kubectl apply -f demo/manifests/real-bug/deployment.yaml
kubectl -n demo rollout status deployment/payments --timeout=120s
kubectl -n demo get pods -l app=payments --show-labels
```

Labels must include `impactgate.io/managed=true`. Terminal 2: `Running`.

### 2. Apply the crash (copy, then apply — do not dirty git)

```bash
rm -rf /tmp/ig-real-bug
cp -a demo/manifests/real-bug /tmp/ig-real-bug
python3 - <<'PY'
from pathlib import Path
p = Path("/tmp/ig-real-bug/deployment.yaml")
text = p.read_text()
needle = """        - name: payments
          image: nginx:1.25
"""
repl = """        - name: payments
          image: nginx:1.25
          command: ["/bin/sh", "-c"]
          args: ["echo 'Traceback (most recent call last):'; echo 'ValueError: boom'; exit 1"]
"""
if needle not in text:
    raise SystemExit("payments container block not found — stop")
p.write_text(text.replace(needle, repl, 1))
print("patched payments to print a traceback and exit 1")
PY
kubectl apply -f /tmp/ig-real-bug/deployment.yaml
```

Expected: `patched payments to print a traceback and exit 1`, then `deployment.apps/payments configured`.

Confirm the live pod is actually crashing:

```bash
kubectl -n demo get pods -l app=payments
```

`CrashLoopBackOff` or `Error` / `0/1 Ready`. If it stays `Running`, the patch did not apply.

### 3. Wait. Do not type.

Terminal 1, first hits:

```text
debouncing demo/payments after CrashLoopBackOff
```

Then, after the same **one-to-two-minute** wait:

```text
dry-run: would escalate on demo/payments (reason=CrashLoopBackOff, mode=dry-run, allowed=['rollback', 'restart'])
```

That is the line. Contrast it with Demo 2’s `would rollback`. Same machinery, opposite action, because the evidence looks like a traceback rather than a bad image.

If you instead see `would restart`, the traceback never reached the classifier — see troubleshooting. Do not ad-lib a rollback.

---

## Metrics

From Terminal 4, against the process in Terminal 1 (default port 8000):

```bash
curl -sS http://127.0.0.1:8000/metrics
```

Always present (even at zero):

```text
impactgate_remediation_total
impactgate_time_to_recovery_seconds
impactgate_findings_total
impactgate_gate_decisions_total
impactgate_llm_calls_total
impactgate_analysis_duration_seconds
```

After Demo 2 you should be able to point at:

```text
impactgate_remediation_total{action="rollback",outcome="dry-run"}
```

After Demo 3:

```text
impactgate_remediation_total{action="escalate",outcome="dry-run"}
```

`impactgate_time_to_recovery_seconds` is the MTTR histogram (clock starts at **detection**, not at action). In dry-run the cluster does not heal, so `_count` stays `0` unless a pod becomes Ready on its own. Point at the series name, not at a made-up number.

`impactgate_findings_total` and `impactgate_gate_decisions_total` are recorded in the **analyze** process, not in kopf. Do not hunt for `broken-selector` on `:8000` after Demo 1.

If curl hangs or connection-refused: Terminal 1 is not running, or metrics never printed `serving /metrics on port 8000`.

---

## Teardown and reset (between rehearsals)

You want a quiet cluster and a reset debounce. Debounce lives in the kopf process memory.

```bash
# Terminal 3
kubectl -n demo delete deployment storefront payments checkout --ignore-not-found
kubectl -n demo delete svc,ing --all --ignore-not-found
rm -rf /tmp/ig-before /tmp/ig-after /tmp/ig-real-bug
git checkout -- demo/manifests
git status
# expect: clean
```

Then **Ctrl-C only Terminal 1** (this is the one time you touch it) and start it again with the same command:

```bash
IMPACTGATE_CONTROLLER_ENABLED=true kopf run -m impactgate.controller.watcher --namespace demo --verbose
```

Restart Terminal 2’s `kubectl -n demo get pods -w` if it exited.

Leave the CRD, namespace, and policy in place. Re-apply if you deleted them:

```bash
kubectl apply -f deploy/crd.yaml
kubectl get ns demo >/dev/null 2>&1 || kubectl create namespace demo
kubectl apply -f deploy/policy.yaml
```

### Full teardown (end of day)

```bash
# Ctrl-C Terminal 1 and Terminal 2 first
kind delete cluster --name impactgate
rm -rf /tmp/ig-before /tmp/ig-after /tmp/ig-real-bug
git checkout -- demo/manifests
```

---

## If something breaks on stage

| Symptom | Likely cause | What to do (exact) |
|---|---|---|
| Terminal 1 has metrics / kopf startup but **no** `debouncing` / `would rollback` / `would escalate` | You started `impactgate controller`, or the pod is missing the managed label | Confirm Terminal 1’s first command line is `kopf run -m impactgate.controller.watcher`. Then: `kubectl -n demo get pods --show-labels` — must contain `impactgate.io/managed=true`. If not, the label is on the Deployment object instead of `spec.template.metadata.labels`. |
| `skipping unmanaged pod …` | Label gate reads pod labels | `kubectl -n demo get deploy storefront -o jsonpath='{.spec.template.metadata.labels}{"\n"}'` must include `"impactgate.io/managed":"true"`. Recreate from `demo/manifests/…/deployment.yaml`. |
| Analyze prints `**Risk:** low` / `no findings` | You analyzed the clean tree, or you edited `matchLabels` instead of the template, or you forgot `--before` after a previous dirty run that you then “fixed” the wrong way | `grep -n 'app:' /tmp/ig-after/deployment.yaml` — template line must be `checkout-v2`, matchLabels `checkout`. Redo the copy + python block. Command is `impactgate analyze /tmp/ig-after --before /tmp/ig-before --no-cache`. |
| Analyze hangs or talks about Gemini | `IMPACTGATE_LLM_PROVIDER` unset | Ctrl-C. `export IMPACTGATE_LLM_PROVIDER=fake` and rerun the same analyze command. |
| Checkov / kube-linter exit 1 | Style checks (CPU, memory, seccomp) | Ignore. Ask whether they mentioned the Service selector. They did not. Continue to `impactgate analyze`. |
| Pod stays `Running` after the Demo 2/3 break | Patch / `set image` did not apply | Demo 2: `kubectl -n demo get deploy storefront -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'` must be `nginx:does-not-exist`. Demo 3: `kubectl -n demo get deploy payments -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'` must contain `Traceback`. Re-apply the break command. |
| `dry-run: would restart` on Demo 3 | Traceback never reached the classifier | Confirm args as above. `kubectl -n demo logs -l app=payments --tail=20` should show `Traceback (most recent call last):`. Recreate: delete the deployment, apply clean YAML, apply `/tmp/ig-real-bug/deployment.yaml` again, wait the full debounce. |
| `mode=dry-run, allowed=[]` in the decision line | Policy not loaded | `kubectl apply -f deploy/policy.yaml`. Look on Terminal 1 for `loaded RemediationPolicy demo/default`. Classification still works; the allow-list is cosmetic in dry-run. |
| `error: resource mapping not found` on policy | CRD not applied first | `kubectl apply -f deploy/crd.yaml` then `kubectl apply -f deploy/policy.yaml`. |
| `ModuleNotFoundError: impactgate` from kopf | Venv not active | `source .venv/bin/activate` in Terminal 1 and rerun `kopf run`. |
| `curl: (7) Failed to connect … 8000` | Controller not running or startup handler did not bind | Terminal 1 must show `serving /metrics on port 8000`. Do not start a second kopf (port in use). |
| You already waited two minutes and still only `debouncing` | Threshold not reached yet, or events stopped | Watch Terminal 2: the pod must still be `ImagePullBackOff` / `CrashLoopBackOff`. If the pod disappeared, the break did not stick. If it is crashing, keep waiting up to five minutes; do not restart kopf unless you are willing to wait again from zero. |
| Someone patched policy to `enforce` | Rollback then needs a 10-minute healthy ReplicaSet and will likely **escalate** instead | `kubectl apply -f deploy/policy.yaml` to restore `dry-run`. Restart kopf. |

---

## One-page crib (print this)

```bash
# Terminal 1 — NEVER TYPE
IMPACTGATE_CONTROLLER_ENABLED=true kopf run -m impactgate.controller.watcher --namespace demo --verbose

# Terminal 2 — NEVER TYPE
kubectl -n demo get pods -w

# Demo 1
rm -rf /tmp/ig-before /tmp/ig-after
cp -a demo/manifests/selector-break /tmp/ig-before
cp -a demo/manifests/selector-break /tmp/ig-after
# run the python relabel block from Demo 1
checkov -d /tmp/ig-after --framework kubernetes --compact
kube-linter lint /tmp/ig-after
IMPACTGATE_LLM_PROVIDER=ollama impactgate analyze /tmp/ig-after --before /tmp/ig-before --no-cache
# key line: ### critical: `broken-selector`

# Demo 2
kubectl apply -f demo/manifests/bad-image/deployment.yaml
kubectl -n demo set image deployment/storefront storefront=nginx:does-not-exist
# wait 1–2 min → dry-run: would rollback on demo/storefront

# Demo 3
kubectl apply -f demo/manifests/real-bug/deployment.yaml
# apply /tmp/ig-real-bug after the python patch block
# wait 1–2 min → dry-run: would escalate on demo/payments

# Metrics
curl -sS http://127.0.0.1:8000/metrics
```
