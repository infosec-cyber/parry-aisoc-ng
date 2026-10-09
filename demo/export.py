import time
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b=p.chromium.launch(args=["--no-sandbox"])
    pg=b.new_page(viewport={"width":1440,"height":810},device_scale_factor=2)
    pg.goto("file:///shared/cybergames/hackathon/parry/slides/parry-deck.html")
    time.sleep(1.5)
    sl=pg.query_selector_all(".slide")
    for n,el in enumerate(sl,1):
        el.scroll_into_view_if_needed(); time.sleep(0.5)
        el.screenshot(path=f"demo/screenshots/slide-{n:02d}.png")
    # PDF (print css makes each slide a page)
    pg.emulate_media(media="print")
    pg.pdf(path="slides/parry-deck.pdf", width="1440px", height="810px", print_background=True)
    print("rendered", len(sl), "slides + pdf")
    b.close()
