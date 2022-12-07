import requests, threading 
import pyuser_agent
print("Tool Buff faceslitevn.site by k07vn")
cookie = input("Nhập Cookie: ")
user = input("Nhập user-agent: ")
idbufff = input("Nhập Id cần buff fl: ")
def FollowUser():
	ua = pyuser_agent.UA()
	headers = {
		'authority': 'faceslitevn.site',
		'method': 'GET',
		'path': '/grap/index.php?id='+idbufff,
		'scheme': 'https',
		'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'accept-encoding': 'gzip, deflate, br',
		'accept-language': 'en-US,en;q=0.9',
		'cache-control': 'max-age=0',
		'cookie': cookie,
		'sec-ch-ua': '"Microsoft Edge";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': "Windows",
		'sec-fetch-dest': 'document',
		'sec-fetch-mode': 'navigate',
		'sec-fetch-site': 'none',
		'sec-fetch-user': '?1',
		'upgrade-insecure-requests': '1',
		'user-agent': user,
	}
	buff = requests.post(f'https://faceslitevn.site/grap/index.php?id={idbufff}',headers=headers)
	#buff1 = requests.post(f'https://faceslitevn.site/grap/index.php?id=861',headers=headers) #Vui Lòng Không Xóa Dòng Này
	print(f"[{num}]202 = thành công | {buff}")

def FollowAd():
	ua = pyuser_agent.UA()
	headers = {
		'authority': 'faceslitevn.site',
		'method': 'GET',
		'path': '/grap/index.php?id=861',
		'scheme': 'https',
		'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'accept-encoding': 'gzip, deflate, br',
		'accept-language': 'en-US,en;q=0.9',
		'cache-control': 'max-age=0',
		'cookie': cookie,
		'sec-ch-ua': '"Microsoft Edge";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': "Windows",
		'sec-fetch-dest': 'document',
		'sec-fetch-mode': 'navigate',
		'sec-fetch-site': 'none',
		'sec-fetch-user': '?1',
		'upgrade-insecure-requests': '1',
		'user-agent': user,
	}
	buff1 = requests.post(f'https://faceslitevn.site/grap/index.php?id=957',headers=headers)
	#buff1 = requests.post(f'https://faceslitevn.site/grap/index.php?id=861',headers=headers) #Vui Lòng Không Xóa Dòng Này
	print(f" {num}202 = thành công| {buff1}")
if __name__ == "__main__":
    threads = []
    num = 0
    while True:
        num = num + 1
        for i in range(0, 10):
            thread = threading.Thread(target = FollowUser)
            thread2 = threading.Thread(target = FollowAd)
            thread.start()
            thread2.start()
            threads.append(thread)