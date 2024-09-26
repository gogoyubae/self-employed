import requests
from dotenv import load_dotenv
import os
from datetime import datetime
from test.industry.brand_interrior import find_interior_cost
from brand_sales import get_brand_frc_bzmn_avrgsls

load_dotenv()
API_KEY = os.environ.get('API_KEY')

BRAND_INFO_URL = "http://apis.data.go.kr/1130000/FftcBrandRlsInfo2_Service/getBrandinfo"

# 브랜드 정보
def get_brand_info(brand_fntn_info, year):
    industry_classification = {}

    brand_info_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "jngBizCrtraYr": year
    }
    response = requests.get(BRAND_INFO_URL, params=brand_info_params)
    total_count = response.json()["totalCount"]
    print(year, "브랜드 총 개수:", total_count)

    # int(total_count / 100 + 2)
    for i in range(1, 10):
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
                brand = {
                    "brand_mnno": item['brandMnno'],                   # 브랜드 모델 번호
                    "jnghdqrtrs_rprsv_nm": item['jnghdqrtrsRprsvNm'],  # 본사 대표 이름
                    "brand_nm": item['brandNm'],                       # 브랜드 이름
                    "induty_lclas_nm": item['indutyLclasNm'],          # 산업 대분류 이름
                    "induty_mlsfc_nm": item['indutyMlsfcNm'],          # 산업 중분류 이름
                    "majr_gds_nm": item['majrGdsNm'],                  # 주요 상품명
                    "fyer_avrg_sls_amt_scope_val": get_brand_frc_bzmn_avrgsls(item['brandMnno']), # 연평균 매출 범위
                }

                if brand["induty_lclas_nm"] not in industry_classification:
                    industry_classification[brand["induty_lclas_nm"]] = {} # 대분류
                if brand["induty_mlsfc_nm"] not in industry_classification[brand["induty_lclas_nm"]]: # 중분류
                    industry_classification[brand["induty_lclas_nm"]][brand["induty_mlsfc_nm"]] = set()
                industry_classification[brand["induty_lclas_nm"]][brand["induty_mlsfc_nm"]].add(brand['majr_gds_nm'])

                find_interior_cost(brand, year) # 인테리어 비용

                if brand['brand_nm'] in brand_fntn_info: # 창업비용
                    # print("========찾음======= 브랜드명 ->", brand['brand_nm'])
                    for key, value in brand_fntn_info[brand['brand_nm']].items():
                        brand[key] = value
                    # print(json.dumps(brand, ensure_ascii=False, indent=4)) # json 형식으로 출력
                    # print("===================")
                brand_info.append(brand)
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    
    print("끝")
    for key, value in industry_classification.items():
        print("대분류 - [", key, "]")
        for key2, value2 in value.items():
            print("     중분류 - [", key2, "]")
            print("             소분류 - [", value2, "]")
    return brand_info
