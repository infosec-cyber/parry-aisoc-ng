import sys, time
from playwright.sync_api import sync_playwright
url = sys.argv[1] if len(sys.argv)>1 else "http://localhost:8050/"
out = sys.argv[2] if len(sys.argv)>2 else "demo/screenshots/dashboard.png"
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    pg = b.new_page(viewport={"width":1600,"height":1000}, device_scale_factor=2)
    pg.goto(url, wait_until="networkidle")
    time.sleep(4)  # let the 2s pollers paint data
    pg.screenshot(path=out, full_page=True)
    print("saved", out)
    b.close()
