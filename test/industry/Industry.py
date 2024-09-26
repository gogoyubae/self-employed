import requests
import json
from dotenv import load_dotenv
import os
from datetime import datetime
from interrior import find_interior_cost
from brand_sales import get_brand_frc_bzmn_avrgsls
from brand_startup_cost import get_brand_fntn_stats

load_dotenv()

BRAND_INFO_URL = "http://apis.data.go.kr/1130000/FftcBrandRlsInfo2_Service/getBrandinfo"

API_KEY = os.environ.get('API_KEY')


# 브랜드 정보
def get_brand_info(brand_fntn_info, year):
    brand_info_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "jngBizCrtraYr": year
    }
    response = requests.get(BRAND_INFO_URL, params=brand_info_params)
    total_count = response.json()["totalCount"]
    print("total_count:", total_count)

    # int(total_count / 100 + 2)
    for i in range(1, 2):
        brand_info_params = {
            "serviceKey": API_KEY,
            "pageNo": i,
            "numOfRows": 100,
            "resultType": "json",
            "jngBizCrtraYr": year
        }

        try:
            response = requests.get(BRAND_INFO_URL, params=brand_info_params)
            response.raise_for_status()

            data = response.json()
            items = data["items"]

            brand_info = []

            for item in items:
                brand_info_entry = {
                    "brand_mnno": item['brandMnno'],                   # 브랜드 모델 번호
                    "jnghdqrtrs_rprsv_nm": item['jnghdqrtrsRprsvNm'],  # 본사 대표 이름
                    "brand_nm": item['brandNm'],                       # 브랜드 이름
                    "induty_lclas_nm": item['indutyLclasNm'],          # 산업 대분류 이름
                    "induty_mlsfc_nm": item['indutyMlsfcNm'],          # 산업 중분류 이름
                    "majr_gds_nm": item['majrGdsNm'],                  # 주요 상품명
                    "fyer_avrg_sls_amt_scope_val": get_brand_frc_bzmn_avrgsls(item['brandMnno']) # 연평균 매출 범위
                }

                find_interior_cost(brand_info_entry, year) # 인테리어 비용

                if brand_info_entry['brand_nm'] in brand_fntn_info: # 창업비용
                    print("========찾음======= 브랜드명 ->", brand_info_entry['brand_nm'])
                    for key, value in brand_fntn_info[brand_info_entry['brand_nm']].items():
                        brand_info_entry[key] = value
                    print(json.dumps(brand_info_entry, ensure_ascii=False, indent=4)) # json 형식으로 출력
                    print("===================")

                brand_info.append(brand_info_entry)
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return brand_info

brand_fntn_info = {}
for year in range(datetime.now().year - 1, 2017, -1): # 창원
    print(year)
    get_brand_fntn_stats(brand_fntn_info, year)
    print("brand_fntn_info 길이:", len(brand_fntn_info))

result = []
year = 2023
# for year in years:
result.extend(get_brand_info(brand_fntn_info, year))