import sys, time
from playwright.sync_api import sync_playwright
pages = sys.argv[1].split(",") if len(sys.argv)>1 else ["pipeline","sponsors","attack","deck"]
with sync_playwright() as p:
    b=p.chromium.launch(args=["--no-sandbox"])
    pg=b.new_page(viewport={"width":1600,"height":1000},device_scale_factor=2)
    pg.goto("http://localhost:8050/",wait_until="domcontentloaded"); time.sleep(6)
    for name in pages:
        pg.click(f'.tab[data-p="{name}"]'); time.sleep(3)
        pg.screenshot(path=f"demo/screenshots/page-{name}.png", full_page=(name in ("pipeline","sponsors")))
        print("shot", name)
    b.close()
