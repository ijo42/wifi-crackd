import asyncio,threading,os,json
from pathlib import Path
from http.server import ThreadingHTTPServer
from playwright.async_api import async_playwright
from wifit3_mobile.engine import Engine
from wifit3_mobile.server import make_handler
from wifit3.dot11.parser import WlanFrameParser

async def main():
 engine=Engine(demo=True);await engine.refresh();await engine.start('demo','all');await asyncio.sleep(0)
 # Receive-only parser fixture, labelled DEMO. No device and no TX.
 fixture=bytes.fromhex('c0000000ffffffffffff02000000000102000000000110000700')
 packet=WlanFrameParser.parse_80211_frame(fixture,rssi=-51)
 engine.disconnect_observations.receive(packet)
 token='local-test-only';loop=asyncio.get_running_loop()
 server=ThreadingHTTPServer(('127.0.0.1',8765),make_handler(engine,loop,token,8765))
 worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
 try:
  async with async_playwright() as p:
   browser=await p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH'),headless=True,args=['--no-sandbox'])
   page=await browser.new_page(viewport={'width':390,'height':844},is_mobile=True,has_touch=True)
   await page.goto('http://127.0.0.1:8765/#'+token)
   await page.locator('#workspace').wait_for(state='visible')
   await page.get_by_role('button',name='Журнал',exact=True).click()
   assert 'deauth 1 / disassoc 0' in await page.locator('#disconnectSummary').inner_text()
   assert 'reason 7' in await page.locator('#disconnectEvents').inner_text()
   assert not await page.locator('#demoNotice').is_hidden()
   assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
   await page.screenshot(path='passive-observation-demo.png',full_page=True)
   await page.get_by_role('button',name='Сети',exact=True).click()
   async with page.expect_download() as dl:await page.locator('#export').click()
   await (await dl.value).save_as('observation-export.json')
   report=json.loads(Path('observation-export.json').read_text())
   assert report['disconnect_observations']['events'][0]['reason']==7
   print('Received fixture → upstream parser → observer → HTTP API → UI log and JSON export: PASS (DEMO, no radio)')
   await browser.close()
 finally:
  await engine.stop();await asyncio.to_thread(server.shutdown);server.server_close()

asyncio.run(main())
