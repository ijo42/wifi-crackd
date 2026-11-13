import asyncio, json, os
from pathlib import Path
from playwright.async_api import async_playwright

async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH'),headless=True,args=['--no-sandbox'])
  page=await browser.new_page(viewport={'width':390,'height':844},device_scale_factor=2,is_mobile=True,has_touch=True)
  errors=[]
  page.on('pageerror',lambda err:errors.append(str(err)))
  connection_url=os.environ.get('CONNECTION_URL')
  token=connection_url.split('#',1)[1] if connection_url else Path(os.environ.get('TOKEN_FILE','demo-token')).read_text().strip()
  await page.request.post('http://127.0.0.1:8765/api/stop',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},data='{}')
  await page.goto('http://127.0.0.1:8765/#'+token)
  await page.locator('#workspace').wait_for(state='visible')
  await page.get_by_role('button',name='Адаптер',exact=True).click()
  await page.locator('#refresh').click()
  await page.locator('#device option[value="demo"]').wait_for(state='attached')
  await page.locator('#authorized').check()
  await page.locator('#start').click()
  await page.wait_for_function("() => document.getElementById('phase').textContent==='В эфире'")
  await page.get_by_role('button',name='Сети',exact=True).click()
  assert await page.locator('.network').count()==4
  assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
  await page.screenshot(path='mobile-scan-demo.png',full_page=True)
  await page.locator('#search').fill('Home')
  assert await page.locator('.network').count()==1
  await page.locator('#search').fill('')
  await page.locator('.network').first.click()
  await page.locator('#details').wait_for(state='visible')
  await page.screenshot(path='mobile-details-demo.png',full_page=True)
  await page.locator('#closeDetails').click()
  await page.locator('#filterBand').select_option('5g')
  assert await page.locator('.network').count()==1
  await page.locator('#filterBand').select_option('all')
  async with page.expect_download() as dl:
   await page.locator('#export').click()
  download=await dl.value
  await download.save_as('export-test.json')
  report=json.loads(Path('export-test.json').read_text())
  assert report['demo'] is True and len(report['networks'])==4
  await page.locator('#stop').click()
  await page.wait_for_function("() => document.getElementById('phase').textContent==='Готов'")
  await page.get_by_role('button',name='Журнал',exact=True).click()
  assert 'USB освобождён' in await page.locator('#logs').inner_text()
  await page.get_by_role('button',name='Адаптер',exact=True).click()
  await page.locator('#disconnect').click()
  await page.locator('#pairing').wait_for(state='visible')
  await page.locator('#token').fill('incorrect');await page.locator('#connect').click()
  await page.locator('#error').wait_for(state='visible')
  # Smallest supported viewport layout.
  await page.set_viewport_size({'width':320,'height':640})
  assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
  assert not errors, errors
  print('UI: pairing, consent, refresh, start, 4 networks, search, details, band filter, JSON export, stop, logs, disconnect, invalid token, 390/320px layout: PASS')
  await browser.close()

asyncio.run(main())
