import re
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import quote_plus
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

APP_TITLE = "API Counter - Coomer/Kemono Profiles (Columns)"
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Referer': 'https://coomer.st/',
    "Accept": "text/css",
}

VIDEO_EXTS = ('.mp4', '.mkv', '.webm', '.mov', '.avi', '.flv', '.wmv', '.m4v')
IMAGE_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff')

URL_PATTERNS = [
    re.compile(r"https?://(?P<site>[^/]+)/(?P<service>[^/]+)/user/(?P<uid>[^/?#]+)", re.IGNORECASE),
    re.compile(r"https?://(?P<site>[^/]+)/users?/(?P<uid>[^/?#]+).*(?:[?&]service=(?P<service>[^&]+))?", re.IGNORECASE),
]

def parse_profile_url(url: str):
    url = url.strip()
    for pat in URL_PATTERNS:
        m = pat.match(url)
        if m:
            gd = m.groupdict()
            site = (gd.get("site") or "").strip()
            service = (gd.get("service") or "").strip().lower()
            uid = (gd.get("uid") or "").strip()
            if site and service and uid:
                return site, service, uid
    return None

def api_fetch_all_posts(site: str, service: str, user_id: str, log_cb=None):
    session = requests.Session()
    posts = []
    offset = 0
    user_id_encoded = quote_plus(user_id)
    while True:
        api_url = f"https://{site}/api/v1/{service}/user/{user_id_encoded}/posts?o={offset}"
        if log_cb:
            log_cb(f"GET {api_url}")
        try:
            r = session.get(api_url, headers=DEFAULT_HEADERS, timeout=30)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and "data" in data:
                chunk = data["data"]
            else:
                chunk = data
            if not chunk:
                break
            posts.extend(chunk)
            offset += 50
        except Exception as e:
            if log_cb:
                log_cb(f"Error: {e}")
            break
    return posts

def build_media_urls_for_post(post: dict, site: str):
    base = f"https://{site}/"
    def _full(path):
        if not path:
            return None
        p = path if str(path).startswith('/') else f'/{path}'
        merged = (base.rstrip('/') + p).replace('://', '§§')
        import re as _re
        merged = _re.sub(r'//+', '/', merged)
        return merged.replace('§§', '://')

    urls = []
    f = post.get('file') or {}
    u = _full(f.get('path') or f.get('url') or f.get('name'))
    if u:
        urls.append(u)
    for att in (post.get('attachments') or []):
        u = _full(att.get('path') or att.get('url') or att.get('name'))
        if u:
            urls.append(u)
    return urls

def classify_media(urls):
    total = 0
    videos = 0
    images = 0
    others = 0
    for u in urls:
        total += 1
        clean = (u.split('?')[0].split('#')[0]).lower()
        ext = clean[clean.rfind('.'): ] if '.' in clean else ''
        if ext in VIDEO_EXTS:
            videos += 1
        elif ext in IMAGE_EXTS:
            images += 1
        else:
            others += 1
    return total, videos, images, others

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1040x720")
        self.minsize(940, 620)

        self.results = []
        self.log_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.executor = None
        self.running = False

        self._build_ui()
        self.after(120, self._drain_log_queue)

    def _build_ui(self):
        # Top frame
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        lbl = ttk.Label(top, text="Paste one or more profile URLs (Coomer/Kemono), one per line:")
        lbl.pack(anchor="w")

        self.txt_urls = tk.Text(top, height=6)
        self.txt_urls.pack(fill="x", pady=6)

        btns = ttk.Frame(top)
        btns.pack(fill="x", pady=(2, 8))

        self.btn_run = ttk.Button(btns, text="Count", command=self.on_run_threaded)
        self.btn_run.pack(side="left")

        self.btn_cancel = ttk.Button(btns, text="Cancel", command=self.on_cancel, state="disabled")
        self.btn_cancel.pack(side="left", padx=6)

        # Log
        self.log_text = tk.Text(top, height=8, state="disabled")
        self.log_text.pack(fill="x")

        # Columns area
        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(fill="both", expand=True)

        headers = ["Site","Service","User ID","Posts","Files (Total)","Videos","Images","Others"]
        self.listboxes = []

        vsb = ttk.Scrollbar(mid, orient="vertical")
        vsb.pack(side="right", fill="y")

        cols_frame = ttk.Frame(mid)
        cols_frame.pack(fill="both", expand=True, side="left")

        for i, h in enumerate(headers):
            col = ttk.Frame(cols_frame)
            col.grid(row=0, column=i, sticky="nsew", padx=(0 if i==0 else 6, 0))
            cols_frame.grid_columnconfigure(i, weight=1)

            hlbl = ttk.Label(col, text=h, anchor="center")
            hlbl.pack(fill="x")

            lb = tk.Listbox(col, exportselection=False)
            lb.pack(fill="both", expand=True)

            self.listboxes.append(lb)

        self.listboxes[0].configure(yscrollcommand=vsb.set)
        vsb.configure(command=self._on_scrollbar)

        for lb in self.listboxes:
            lb.bind("<MouseWheel>", self._on_mousewheel)
            lb.bind("<Button-4>", self._on_mousewheel)
            lb.bind("<Button-5>", self._on_mousewheel)

        self.status = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status, anchor="w", padding=(10, 4))
        status_bar.pack(fill="x", side="bottom")

    def _on_scrollbar(self, *args):
        for lb in self.listboxes:
            lb.yview(*args)

    def _on_mousewheel(self, event):
        delta = 0
        if event.num == 5 or event.delta < 0:
            delta = 1
        elif event.num == 4 or event.delta > 0:
            delta = -1
        for lb in self.listboxes:
            lb.yview_scroll(delta, "units")
        return "break"

    def log(self, msg: str):
        self.log_queue.put(msg)

    def _drain_log_queue(self):
        for _ in range(200):
            if self.log_queue.empty():
                break
            msg = self.log_queue.get()
            self.log_text.configure(state="normal")
            self.log_text.insert("end", msg + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(150, self._drain_log_queue)

    def _set_running(self, running: bool):
        self.running = running
        self.btn_run.configure(state="disabled" if running else "normal")
        self.btn_cancel.configure(state="normal" if running else "disabled")
        self.status.set("Processing..." if running else "Ready.")

    def on_run_threaded(self):
        if self.running:
            return
        self.results = []
        for lb in self.listboxes:
            lb.delete(0, "end")

        raw = self.txt_urls.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("Warning", "Please enter at least one profile URL.")
            return
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        self.status.set(f"Queued {len(urls)} profile(s)...")
        self.stop_flag.clear()
        self._set_running(True)

        threading.Thread(target=self._run_in_threads, args=(urls,), daemon=True).start()

    def _run_in_threads(self, urls):
        self.executor = ThreadPoolExecutor(max_workers=min(8, max(2, len(urls))))
        futures = [self.executor.submit(self._process_single_url, url) for url in urls]

        for fut in as_completed(futures):
            if self.stop_flag.is_set():
                break
            row = fut.result()
            if row is None:
                continue
            self.after(0, self._add_row_to_columns, row)

        self.after(0, self._finalize_run)

    def _process_single_url(self, url: str):
        if self.stop_flag.is_set():
            return None
        parsed = parse_profile_url(url)
        if not parsed:
            self.log(f"[SKIP] Could not parse: {url}")
            return None
        site, service, uid = parsed

        posts = api_fetch_all_posts(site, service, uid, log_cb=self.log)
        post_count = len(posts)

        all_urls = []
        for p in posts:
            all_urls.extend(build_media_urls_for_post(p, site))
        total, vids, imgs, others = classify_media(all_urls)

        return {
            "site": site,
            "service": service,
            "user_id": uid,
            "posts": post_count,
            "media_total": total,
            "videos": vids,
            "images": imgs,
            "others": others,
        }

    def _add_row_to_columns(self, row):
        self.results.append(row)
        values = (
            row["site"], row["service"], row["user_id"],
            str(row["posts"]), str(row["media_total"]), str(row["videos"]),
            str(row["images"]), str(row["others"])
        )
        for lb, val in zip(self.listboxes, values):
            lb.insert("end", val)
        self.status.set(f"Results: {len(self.results)} profile(s).")

    def _finalize_run(self):
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.executor = None
        self._set_running(False)

    def on_cancel(self):
        if not self.running:
            return
        self.stop_flag.set()
        self.status.set("Cancelling...")
        self.btn_cancel.configure(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()
