#!/usr/bin/env python3
"""
XSS Testing GUI (loads payloads from xss.txt)

- Loads all payloads from local file (default: /mnt/data/xss.txt) and merges with built-in payloads.
- Tests payloads against URL parameters and HTML forms.
- Injects JS hook before page loads to catch early alerts/prompts.
- Thread-safe and multi-threaded (configurable).
- Exports JSON and HTML reports.

Dependencies:
    pip install selenium bs4
    optional: pip install undetected-chromedriver

Notes:
    Ensure Chrome/Chromium + matching ChromeDriver are available, or install undetected-chromedriver.
"""
from __future__ import annotations
import os
import time
import json
import html
import logging
import threading
from queue import Queue, Empty
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException,
    NoAlertPresentException,
    UnexpectedAlertPresentException,
    WebDriverException,
    JavascriptException,
)

# -----------------------
# Configuration
# -----------------------
PAYLOAD_FILE = "/mnt/data/xss.txt"  # default: uploaded file location
DEFAULT_TIMEOUT = 18
DEFAULT_THREADS = 3
WINDOW_SIZE = "1366,1024"

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# -----------------------
# Built-in (baseline) payloads
# -----------------------
BUILTIN_PAYLOADS = [
    '<script>alert("XSS");</script>',
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<script>window.xssDetected=true;</script>",
    "<img src=x onerror=window.xssDetected=true;>",
    "';window.xssDetected=true;//",
    "\";window.xssDetected=true;//",
    "`;window.xssDetected=true;//",
    # ... (you can add more built-ins here if desired)
]

# -----------------------
# Utilities
# -----------------------
def load_payloads_from_file(path: str) -> list[str]:
    """Load payloads from file preserving lines exactly (including duplicates)."""
    if not path or not os.path.isfile(path):
        logging.warning("Payload file not found: %s", path)
        return []
    payloads = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ln = line.rstrip("\n")
            if ln != "":
                payloads.append(ln)
    logging.info("Loaded %d payloads from %s", len(payloads), path)
    return payloads

def safe_join_url(base: str, action: str | None) -> str:
    """Resolve form action to absolute URL relative to base url."""
    if not action:
        return base
    parsed = urlparse(base)
    if action.startswith("http://") or action.startswith("https://"):
        return action
    root = f"{parsed.scheme}://{parsed.netloc}"
    if action.startswith("/"):
        return root + action
    # relative path
    base_path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
    return f"{root}{base_path}/{action}"

def looks_unescaped_dangerous(html_text: str) -> bool:
    """Heuristic to detect unescaped dangerous constructs in the page source."""
    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return False
    # script tags present?
    if soup.find("script"):
        return True
    # elements with on* attributes
    for el in soup.find_all(True):
        for attr in el.attrs:
            if isinstance(attr, str) and attr.lower().startswith("on"):
                return True
    # svg or math presence
    if soup.find("svg") or soup.find("math"):
        return True
    text = html_text.lower()
    markers = ["<script", "onerror=", "onload=", "<svg", "javascript:"]
    return any(m in text for m in markers)

# -----------------------
# Main GUI + Scanner
# -----------------------
class XSSScannerGUI:
    def __init__(self, root: tk.Tk, payload_file: str = PAYLOAD_FILE):
        self.root = root
        self.root.title("XSS Scanner — payloads from file")
        self.root.geometry("900x700")

        # ---- top controls ----
        tk.Label(root, text="Target URL:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.url_entry = tk.Entry(root, width=90)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky="w", padx=8)
        self.url_entry.insert(0, "http://example.com/page?search=test")

        tk.Label(root, text="Payload file:").grid(row=1, column=0, sticky="w", padx=8)
        self.payload_file_entry = tk.Entry(root, width=60)
        self.payload_file_entry.grid(row=1, column=1, sticky="w", padx=8)
        self.payload_file_entry.insert(0, payload_file)
        tk.Button(root, text="Browse", command=self.browse_payload_file).grid(row=1, column=2, sticky="w")

        tk.Label(root, text="Proxy (host:port) [optional]:").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        self.proxy_entry = tk.Entry(root, width=32)
        self.proxy_entry.grid(row=2, column=1, sticky="w", padx=8)

        self.headless_var = tk.BooleanVar(value=True)
        tk.Checkbutton(root, text="Headless", variable=self.headless_var).grid(row=2, column=2, sticky="w")

        tk.Label(root, text="Threads:").grid(row=2, column=3, sticky="e")
        self.threads_var = tk.IntVar(value=DEFAULT_THREADS)
        tk.Spinbox(root, from_=1, to=10, textvariable=self.threads_var, width=4).grid(row=2, column=4, sticky="w")

        self.start_button = tk.Button(root, text="Start", command=self.start_scan)
        self.start_button.grid(row=0, column=4, sticky="e", padx=8)

        # ---- progress and log ----
        self.progress_label = tk.Label(root, text="Progress: 0/0")
        self.progress_label.grid(row=3, column=0, columnspan=5, sticky="w", padx=8)

        self.log_area = scrolledtext.ScrolledText(root, height=30, width=110, state="disabled")
        self.log_area.grid(row=4, column=0, columnspan=6, padx=8, pady=8)

        tk.Button(root, text="Save JSON Report", command=self.save_json_report, state="normal").grid(row=5, column=3, sticky="e", padx=8)
        tk.Button(root, text="Save HTML Report", command=self.save_html_report, state="normal").grid(row=5, column=4, sticky="e", padx=8)

        # ---- state ----
        self.payload_file = payload_file
        self.payloads_all: list[str] = []
        self.results: list[dict] = []
        self.queue: Queue = Queue()
        self.threads: list[threading.Thread] = []
        self.lock = threading.Lock()
        self.total_tasks = 0
        self.completed_tasks = 0

    # ---- GUI helpers ----
    def log(self, message: str):
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")
        logging.info(message)

    def update_progress_label(self):
        self.progress_label.config(text=f"Progress: {self.completed_tasks}/{self.total_tasks}")

    def browse_payload_file(self):
        path = filedialog.askopenfilename(title="Select payload file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.payload_file_entry.delete(0, tk.END)
            self.payload_file_entry.insert(0, path)

    # ---- WebDriver setup ----
    def setup_driver(self):
        options = Options()
        if self.headless_var.get():
            # headless new is more compatible with modern Chrome
            options.add_argument("--headless=new")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-notifications")
        options.add_argument(f"--window-size={WINDOW_SIZE}")
        proxy = self.proxy_entry.get().strip()
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")

        driver = None
        # try undetected_chromedriver if available
        try:
            import undetected_chromedriver as uc  # type: ignore
            driver = uc.Chrome(options=options)
        except Exception:
            # fallback to normal selenium chromedriver
            driver = webdriver.Chrome(options=options)

        # ensure page load timeout
        try:
            driver.set_page_load_timeout(DEFAULT_TIMEOUT)
        except Exception:
            pass

        # preload JS hook before navigation using CDP when possible
        js_hook = r"""
            Object.defineProperty(window, 'xssDetected', {value:false, writable:true});
            (function(){
                var wrap = function(orig){
                    return function(){
                        try{ window.xssDetected = true; }catch(e){}
                        try{ return orig.apply(this, arguments); }catch(e){ return true; }
                    };
                };
                if (window.alert) window.alert = wrap(window.alert);
                if (window.confirm) window.confirm = wrap(window.confirm);
                if (window.prompt) window.prompt = wrap(window.prompt);
            })();
        """
        try:
            # selenium Chrome supports execute_cdp_cmd
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": js_hook})
        except Exception:
            # some drivers may not support CDP - we'll inject after navigation as fallback
            logging.debug("CDP injection failed; will attempt post-navigation hook injection.")

        return driver

    def ensure_hook(self, driver):
        """Fallback: inject hook after navigation when CDP injection isn't available."""
        js = r"""
            if (typeof window.xssDetected === 'undefined') {
                window.xssDetected = false;
                (function(){
                  var wrap = function(orig){
                    return function(){
                      try{ window.xssDetected = true; }catch(e){}
                      try{ return orig.apply(this, arguments); }catch(e){return true;}
                    };
                  };
                  if (window.alert) window.alert = wrap(window.alert);
                  if (window.confirm) window.confirm = wrap(window.confirm);
                  if (window.prompt) window.prompt = wrap(window.prompt);
                })();
            }
        """
        try:
            driver.execute_script(js)
        except Exception:
            pass

    # ---- URL & form helpers ----
    def get_url_params(self, url: str) -> dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    def build_url_with_payload(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def extract_forms_from_page(self, page_source: str) -> list[dict]:
        soup = BeautifulSoup(page_source, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            form_details = {"action": form.get("action"), "method": (form.get("method") or "get").lower(), "inputs": []}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                typ = input_tag.get("type", "text")
                if name:
                    form_details["inputs"].append({"name": name, "type": typ})
            forms.append(form_details)
        return forms

    def fill_and_submit_form(self, driver, base_url: str, form: dict, payload: str) -> bool:
        """
        Attempts to find the corresponding form in the DOM, fills inputs (skipping hidden),
        sets payload for those fields, and submits (prefer click on submit).
        """
        try:
            dom_forms = driver.find_elements(By.TAG_NAME, "form")
            if not dom_forms:
                self.log("No forms in DOM to submit.")
                return False

            # try to match by action if available
            target = None
            expected_action = safe_join_url(base_url, form.get("action"))
            for f in dom_forms:
                try:
                    action = f.get_attribute("action") or ""
                    # canonicalize small things
                    if action and expected_action and (action.startswith(expected_action) or expected_action.startswith(action)):
                        target = f
                        break
                except Exception:
                    continue
            if target is None:
                target = dom_forms[0]

            # fill inputs
            for input_info in form.get("inputs", []):
                name = input_info.get("name")
                typ = (input_info.get("type") or "text").lower()
                try:
                    elem = target.find_element(By.NAME, name)
                    if typ == "hidden":
                        # preserve hidden input value
                        continue
                    try:
                        elem.clear()
                    except Exception:
                        pass
                    try:
                        elem.send_keys(payload)
                    except Exception:
                        # some elements might not support send_keys, ignore
                        pass
                except Exception as e:
                    # may not exist or be dynamic; continue
                    logging.debug("Could not set input %s: %s", name, e)

            # attempt to click submit button if present
            try:
                submit_btn = target.find_element(By.CSS_SELECTOR, "[type=submit], button[type=submit], button:not([type])")
                try:
                    submit_btn.click()
                except Exception:
                    # fallback to JS click
                    driver.execute_script("arguments[0].click();", submit_btn)
            except Exception:
                # fallback to form.submit()
                try:
                    target.submit()
                except Exception:
                    # last resort: try to find any <input type=submit>
                    try:
                        sbtn = target.find_element(By.TAG_NAME, "input")
                        driver.execute_script("arguments[0].click();", sbtn)
                    except Exception:
                        logging.debug("Could not submit form by any method.")
            # small wait
            time.sleep(2.4)
            return True
        except Exception as e:
            logging.debug("Form submission exception: %s", e)
            return False

    # ---- detection ----
    def detect_xss(self, driver) -> tuple[bool, str | None]:
        # check alert
        try:
            alert = driver.switch_to.alert
            try:
                text = alert.text
            except Exception:
                text = "alert"
            try:
                alert.accept()
            except Exception:
                pass
            return True, f"Alert popup ({text})"
        except NoAlertPresentException:
            pass
        except UnexpectedAlertPresentException:
            try:
                alert = driver.switch_to.alert
                alert.accept()
                return True, "Unexpected alert"
            except Exception:
                pass

        # check js hook
        try:
            detected = driver.execute_script("return !!window.xssDetected;")
            if detected:
                return True, "JS hook triggered"
        except JavascriptException:
            pass
        except Exception:
            pass

        return False, None

    # ---- scanning logic per vector ----
    def test_url_param(self, driver, base_url: str, param: str, payloads: list[str]):
        """Iterate payloads and test against a given parameter."""
        for payload in payloads:
            test_url = self.build_url_with_payload(base_url, param, payload)
            self.log(f"[PARAM] testing param '{param}' with payload: {payload!r}")
            try:
                driver.get(test_url)
                self.ensure_hook(driver)
                time.sleep(1.8)

                vulnerable, evidence = self.detect_xss(driver)
                if vulnerable:
                    self.record_result({
                        "vector": "URL Parameter",
                        "parameter": param,
                        "payload": payload,
                        "evidence": evidence,
                        "url": test_url,
                    })
                    # return early on detection for this parameter
                    return

                # heuristic reflection check
                page_source = driver.page_source or ""
                if payload and payload in page_source and looks_unescaped_dangerous(page_source):
                    self.record_result({
                        "vector": "URL Parameter (reflection heuristic)",
                        "parameter": param,
                        "payload": payload,
                        "evidence": "Possible unescaped reflection",
                        "url": test_url,
                    })
                    return

            except TimeoutException:
                self.log(f"[PARAM] timeout for {test_url}")
            except WebDriverException as e:
                self.log(f"[PARAM] WebDriver error: {e}")
                # don't spam on driver errors; try next payload/param
            except Exception as e:
                self.log(f"[PARAM] unexpected error: {e}")

    def test_form(self, driver, base_url: str, form: dict, payloads: list[str]):
        """Test a single form with payloads (fill inputs & submit)."""
        for payload in payloads:
            self.log(f"[FORM] testing form '{form.get('action')}' with payload: {payload!r}")
            try:
                driver.get(base_url)
                self.ensure_hook(driver)
                time.sleep(1.2)

                submitted = self.fill_and_submit_form(driver, base_url, form, payload)
                if not submitted:
                    continue

                # allow script execution
                self.ensure_hook(driver)
                time.sleep(2.0)

                vulnerable, evidence = self.detect_xss(driver)
                if vulnerable:
                    self.record_result({
                        "vector": "Form",
                        "form_action": safe_join_url(base_url, form.get("action")),
                        "payload": payload,
                        "evidence": evidence,
                        "url": base_url,
                    })
                    return

                page_source = driver.page_source or ""
                # reflection heuristic
                if payload and payload in page_source and looks_unescaped_dangerous(page_source):
                    self.record_result({
                        "vector": "Form (reflection heuristic)",
                        "form_action": safe_join_url(base_url, form.get("action")),
                        "payload": payload,
                        "evidence": "Possible unescaped reflection",
                        "url": base_url,
                    })
                    return

            except TimeoutException:
                self.log("[FORM] page timeout")
            except WebDriverException as e:
                self.log(f"[FORM] WebDriver error: {e}")
            except Exception as e:
                self.log(f"[FORM] unexpected error: {e}")

    # ---- worker & orchestration ----
    def worker(self, task_queue: Queue, base_url: str, payloads: list[str]):
        driver = None
        try:
            driver = self.setup_driver()
            while True:
                try:
                    task = task_queue.get_nowait()
                except Empty:
                    break

                try:
                    if task.get("type") == "param":
                        self.test_url_param(driver, base_url, task["param"], payloads)
                    elif task.get("type") == "form":
                        # re-extract forms just-in-time (page might be dynamic)
                        try:
                            driver.get(base_url)
                            time.sleep(1.2)
                            page_forms = self.extract_forms_from_page(driver.page_source)
                        except Exception:
                            page_forms = []
                        idx = task.get("index", 0)
                        if 0 <= idx < len(page_forms):
                            self.test_form(driver, base_url, page_forms[idx], payloads)
                    # mark task done and increment completed counter
                finally:
                    with self.lock:
                        self.completed_tasks += 1
                        self.update_progress_label()
                    task_queue.task_done()
        except Exception as e:
            logging.debug("Worker top-level exception: %s", e)
        finally:
            try:
                if driver:
                    driver.quit()
            except Exception:
                pass

    def record_result(self, item: dict):
        with self.lock:
            self.results.append(item)
        self.log(f"[VULN] {json.dumps(item, ensure_ascii=False)}")

    # ---- UI actions ----
    def start_scan(self):
        # reset
        self.results = []
        self.queue = Queue()
        self.threads = []
        self.total_tasks = 0
        self.completed_tasks = 0
        self.update_progress_label()

        base_url = self.url_entry.get().strip()
        if not base_url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        # load payloads: builtins + file lines (preserving duplicates)
        pf = self.payload_file_entry.get().strip() or PAYLOAD_FILE
        file_payloads = load_payloads_from_file(pf)
        # payloads_all preserves order: built-ins first then file payloads (you asked to include all)
        self.payloads_all = list(BUILTIN_PAYLOADS) + file_payloads
        self.log(f"Total payloads to test: {len(self.payloads_all)} (built-in + file)")

        # queue URL params
        params = list(self.get_url_params(base_url).keys())
        for p in params:
            self.queue.put({"type": "param", "param": p})

        # one quick pass to find initial forms (we'll re-extract forms in workers)
        temp_driver = None
        try:
            temp_driver = self.setup_driver()
            try:
                temp_driver.get(base_url)
                time.sleep(1.6)
                initial_forms = self.extract_forms_from_page(temp_driver.page_source)
            except Exception:
                initial_forms = []
        finally:
            try:
                if temp_driver:
                    temp_driver.quit()
            except Exception:
                pass

        for idx in range(len(initial_forms)):
            self.queue.put({"type": "form", "index": idx})

        # total tasks
        self.total_tasks = self.queue.qsize()
        self.update_progress_label()
        if self.total_tasks == 0:
            self.log("No URL parameters or forms found to test.")
            return

        # spawn workers
        max_threads = max(1, min(self.threads_var.get() or DEFAULT_THREADS, self.total_tasks))
        for _ in range(max_threads):
            t = threading.Thread(target=self.worker, args=(self.queue, base_url, self.payloads_all), daemon=True)
            t.start()
            self.threads.append(t)

        self.log(f"Started {len(self.threads)} worker(s).")
        self.root.after(800, self.check_workers)

    def check_workers(self):
        alive = any(t.is_alive() for t in self.threads)
        if alive or not self.queue.empty():
            self.root.after(800, self.check_workers)
            return
        # finished
        self.log("Scanning completed.")
        self.show_report()

    def show_report(self):
        self.log("\n=== XSS Report ===")
        if not self.results:
            self.log("No vulnerabilities detected.")
            return
        for idx, r in enumerate(self.results, 1):
            v = r.get("vector", "")
            target = r.get("parameter") or r.get("form_action") or r.get("url")
            payload = r.get("payload", "")
            evidence = r.get("evidence", "")
            self.log(f"{idx}. [{v}] Target: {target}")
            self.log(f"    Payload: {payload}")
            self.log(f"    Evidence: {evidence}")
            self.log(f"    URL: {r.get('url')}\n")

    def save_json_report(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("Saved", f"JSON report written to {path}")

    def save_html_report(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html"), ("All files", "*.*")])
        if not path:
            return
        rows = []
        for r in self.results:
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(r.get('vector','')))}</td>"
                f"<td>{html.escape(str(r.get('parameter','') or r.get('form_action','')))}</td>"
                f"<td><code>{html.escape(str(r.get('payload','')))}</code></td>"
                f"<td>{html.escape(str(r.get('evidence','')))}</td>"
                f"<td><a href='{html.escape(str(r.get('url','')))}'>{html.escape(str(r.get('url','')))}</a></td>"
                "</tr>"
            )
        content = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>XSS Report</title>
<style>body{{font-family:system-ui,Arial;}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px}}th{{background:#eee}}</style>
</head><body>
<h1>XSS Scan Report</h1>
<p>Findings: {len(self.results)}</p>
<table><thead><tr><th>Vector</th><th>Target</th><th>Payload</th><th>Evidence</th><th>URL</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"HTML report written to {path}")

# -----------------------
# Entrypoint
# -----------------------
def main():
    root = tk.Tk()
    app = XSSScannerGUI(root, payload_file=PAYLOAD_FILE)
    root.mainloop()

if __name__ == "__main__":
    main()
