import sys, time
from playwright.sync_api import sync_playwright
idxs = [int(x) for x in sys.argv[1].split(",")]
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    pg = b.new_page(viewport={"width":1440,"height":810}, device_scale_factor=2)
    pg.goto("file:///shared/cybergames/hackathon/parry/slides/parry-deck.html")
    time.sleep(1.5)
    slides = pg.query_selector_all(".slide")
    for n in idxs:
        slides[n-1].scroll_into_view_if_needed(); time.sleep(0.8)
        slides[n-1].screenshot(path=f"demo/screenshots/slide-{n:02d}.png")
        print("slide", n)
    b.close()
