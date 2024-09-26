import requests
from dotenv import load_dotenv
import os

load_dotenv()
OPEN_DATA_API_KEY = os.environ.get('OPEN_DATA_API_KEY')

FFTC_BRAND_FNTN_STATS_URL = "http://apis.data.go.kr/1130000/FftcBrandFntnStatsService/getBrandFntnStats"

# 브랜드별 창업 비용
def get_brand_fntn_stats(brand_fntn_info, year):
    brand_fntn_stats_params = {
        "serviceKey": OPEN_DATA_API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "yr": year
    }

    response = requests.get(FFTC_BRAND_FNTN_STATS_URL, params=brand_fntn_stats_params)
    total_count = response.json()["totalCount"]
    
    for i in range(1, int(total_count / 100 + 2)): # 100개씩 저장
        brand_fntn_stats_params = {
            "serviceKey": OPEN_DATA_API_KEY,
            "pageNo": i,
            "numOfRows": 100,
            "resultType": "json",
            "yr": year
        }

        try:
            response = requests.get(FFTC_BRAND_FNTN_STATS_URL, params=brand_fntn_stats_params)
            data = response.json()
            items = data["items"]
            
            for item in items:
                if item['brandNm'] not in brand_fntn_info:
                    brand_fntn_info[item['brandNm']] = {
                        "jng_bzmn_jng_amt": item['jngBzmnJngAmt'],           # 가맹 사업자 가맹 금액 (3300)
                        "jng_bzmn_edu_amt": item['jngBzmnEduAmt'],           # 가맹 사업자 교육비 (2200)
                        "jng_bzmn_assrnc_amt": item['jngBzmnAssrncAmt'],     # 가맹 사업자 보증금 (1000)
                        "jng_bzmn_etc_amt": item['jngBzmnEtcAmt'],           # 가맹 사업자 기타 금액 (29133)
                        "smtn_amt": item['smtnAmt']                          # 합계 금액 (35633)
                    }
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")