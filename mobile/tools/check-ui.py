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
  await page.get_by_role('button',name='Модуль',exact=True).click()
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
  # --- 0.4.2: campaign card (DEMO shims: synthetic results, no radio) ---
  await page.locator('#campaignBtns button').first.wait_for(state='visible')
  assert 'Кампании не запущены' in await page.locator('#campaignStatus').inner_text()
  await page.get_by_role('button',name='Deauth',exact=True).click()
  await page.wait_for_function("() => document.getElementById('campaignStatus').textContent.includes('Deauth:')")
  await page.wait_for_function("() => document.getElementById('hashCount').textContent==='1'",timeout=15000)
  await page.wait_for_function("() => document.getElementById('campaignStatus').textContent.includes('захват получен')",timeout=15000)
  # PMKID on the same target: harvest registers a second hash
  await page.get_by_role('button',name='PMKID',exact=True).click()
  await page.wait_for_function("() => document.getElementById('campaignStatus').textContent.includes('PMKID получен')",timeout=15000)
  await page.wait_for_function("() => document.getElementById('hashCount').textContent==='2'",timeout=15000)
  await page.locator('#closeDetails').click()
  # WPS on a target that advertises WPS
  await page.locator('.network',has_text='Home Network').first.click()
  await page.locator('#details').wait_for(state='visible')
  await page.get_by_role('button',name='WPS PIN',exact=True).click()
  await page.wait_for_function("() => document.getElementById('campaignStatus').textContent.includes('WPS PIN найден')",timeout=15000)
  assert '12345670' in await page.locator('#campaignStatus').inner_text()
  await page.locator('#closeDetails').click()
  # --- 0.4: hashes tab + export gating ---
  await page.get_by_role('button',name='Хеши',exact=True).click()
  await page.wait_for_function("() => document.getElementById('hashSummary').textContent.includes('Уникальных хешей: 2')")
  assert await page.locator('#hashNets .tag').count()==1
  assert not await page.locator('#exportHashes').is_disabled()
  assert await page.locator('#hashLines').is_visible()
  # --- 0.4: Hashtopolis dry-run passes in DEMO; real send is blocked ---
  await page.locator('#htpUrl').fill('http://127.0.0.1:1')  # dry-run must not contact anything
  await page.locator('#htpDry').check()
  await page.locator('#htpSend').click()
  await page.wait_for_function("() => !document.getElementById('htpResult').hidden")
  result=json.loads(await page.locator('#htpResult').inner_text())
  assert result['dry_run'] is True and result['total']==2, result
  await page.locator('#htpDry').uncheck()
  await page.locator('#htpSend').click()
  await page.wait_for_function("() => !document.getElementById('error').hidden")
  assert 'DEMO' in await page.locator('#error').inner_text()
  # --- classic flow + 0.4.2 filters ---
  await page.get_by_role('button',name='Сети',exact=True).click()
  await page.locator('#filterBand').select_option('5g')
  assert await page.locator('.network').count()==1
  await page.locator('#filterBand').select_option('all')
  await page.locator('#filterEnc').select_option('WPA2')
  assert await page.locator('.network').count()==3           # WPA2 + WPA2/WPA3, OPEN excluded
  await page.locator('#filterEnc').select_option('OPEN')
  assert await page.locator('.network').count()==1
  await page.locator('#filterEnc').select_option('all')
  await page.locator('#filterTargets').select_option('potential')
  assert await page.locator('.network').count()==0           # clients AND no hashes: none in DEMO
  await page.locator('#filterTargets').select_option('any')
  await page.locator('#sort').select_option('clients')       # sorts without error
  assert await page.locator('.network').count()==4
  async with page.expect_download() as dl:
   await page.locator('#export').click()
  download=await dl.value
  await download.save_as('export-test.json')
  report=json.loads(Path('export-test.json').read_text())
  assert report['demo'] is True and len(report['networks'])==4
  await page.get_by_role('button',name='Журнал',exact=True).click()
  assert 'запущен против' in await page.locator('#logs').inner_text()
  await page.get_by_role('button',name='Сети',exact=True).click()
  await page.locator('#stop').click()
  await page.wait_for_function("() => document.getElementById('phase').textContent==='Готов'")
  await page.get_by_role('button',name='Журнал',exact=True).click()
  assert 'USB освобождён' in await page.locator('#logs').inner_text()
  await page.get_by_role('button',name='Модуль',exact=True).click()
  await page.locator('#disconnect').click()
  await page.locator('#pairing').wait_for(state='visible')
  await page.locator('#token').fill('incorrect');await page.locator('#connect').click()
  await page.locator('#error').wait_for(state='visible')
  # Smallest supported viewport layout.
  await page.set_viewport_size({'width':320,'height':640})
  assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
  assert not errors, errors
  # --- 0.4: graceful module shutdown without Ctrl+C (server exits; must be last) ---
  await page.locator('#token').fill(token);await page.locator('#connect').click()
  await page.locator('#workspace').wait_for(state='visible')
  await page.get_by_role('button',name='Модуль',exact=True).click()
  await page.locator('#shutdownModule').click()          # arm
  await page.locator('#shutdownModule').click()          # confirm
  await page.wait_for_function("() => !document.getElementById('workspace').hidden===false && document.getElementById('pairing').hidden===false")
  assert 'Модуль остановлен' in await page.locator('#linkState').inner_text()
  await page.wait_for_timeout(1500)                      # give the server time to exit
  try:
   await page.request.post('http://127.0.0.1:8765/api/state',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},data='{}')
   raise AssertionError('server still alive after shutdown')
  except Exception:
   pass
  print('UI 0.4.4: pairing, consent, USB refresh, start, 4 networks, search, focus+deauth+pmkid+wps DEMO, targets-filter+sort, hashes tab, hc22000 export gate, htp dry-run, DEMO send block, band filter, JSON export, logs, disconnect, invalid token, 320px layout, graceful shutdown: PASS')
  await browser.close()

asyncio.run(main())
