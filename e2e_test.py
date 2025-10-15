from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("http://localhost:3001/scanners")

    # Click the "New XSS Scan" button
    page.get_by_role("button", name="New XSS Scan").click()

    # Wait for the scan window to appear
    scan_window = page.locator(".react-draggable").last
    expect(scan_window).to_be_visible()

    # Fill in the target URL
    scan_window.get_by_placeholder("Enter URL").fill("http://testphp.vulnweb.com/")

    # Click the "Start XSS Scan" button
    scan_window.get_by_role("button", name="Start XSS Scan").click()

    # Wait for the result to appear, indicating the scan is complete
    result_pre = scan_window.locator("pre")
    expect(result_pre).to_be_visible(timeout=60000) # Wait up to 60 seconds

    # Take a screenshot
    page.screenshot(path="verification.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
