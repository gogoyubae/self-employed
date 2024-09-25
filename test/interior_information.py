import requests
import json
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

BRAND_INFO_URL = "http://apis.data.go.kr/1130000/FftcBrandRlsInfo2_Service/getBrandinfo"
BRAND_FRCS_BZM_INTRRCTINFO_URL = "http://apis.data.go.kr/1130000/FftcBrandFrcsIntInfo2_Service/getbrandFrcsBzmnIntrrctinfo"
API_KEY = os.environ.get('API_KEY')


def get_interior_cost(brand_info, brand_mnno, year):
    brand_frcs_bzm_intrrctinfo_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "jngBizCrtraYr": year,
        "brandMnno": brand_mnno
    }

    response = requests.get(BRAND_FRCS_BZM_INTRRCTINFO_URL, params=brand_frcs_bzm_intrrctinfo_params)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")

    try:
        data = response.json()
        if not ('items' in data and data['items']):
            return
    
        item = data['items'][0]
        brand_info.update({
            "unit_ar_intrr_amt_scope_val": item['unitArIntrrAmtScopeVal'],  # 단위 면적 계약 금액 범위
            "stor_crtra_ar": item['storCrtraAr'],                           # 매장 계약 면적
            "intrr_amt_scope_val": item['intrrAmtScopeVal']                 # 인테리어 총 금액 범위
        })
    except ValueError as e:
        print("JSONDecodeError:", e)
        print("Response Text:", response.text)


def get_brand_info(year):
    brand_info_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "jngBizCrtraYr": year
    }
    response = requests.get(BRAND_INFO_URL, params=brand_info_params)
    total_count = response.json()["totalCount"]

    for i in range(1, int(total_count / 100 + 2)):
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
                brandMnno = item['brandMnno']          # 브랜드 모델 번호
                jnghdqrtrsRprsvNm = item['jnghdqrtrsRprsvNm']  # 본사 대표 이름
                brandNm = item['brandNm']              # 브랜드 이름
                indutyLclasNm = item['indutyLclasNm']  # 산업 대분류 이름
                indutyMlsfcNm = item['indutyMlsfcNm']  # 산업 중분류 이름
                majrGdsNm = item['majrGdsNm']          # 주요 상품명

                brand_info_entry = {
                    "brand_mnno": brandMnno,                   # 브랜드 모델 번호
                    "jnghdqrtrs_rprsv_nm": jnghdqrtrsRprsvNm,  # 본사 대표 이름
                    "brand_nm": brandNm,                       # 브랜드 이름
                    "induty_lclas_nm": indutyLclasNm,          # 산업 대분류 이름
                    "induty_mlsfc_nm": indutyMlsfcNm,          # 산업 중분류 이름
                    "majr_gds_nm": majrGdsNm                   # 주요 상품명
                }
                
                get_interior_cost(brand_info_entry, brandMnno, year)
                brand_info.append(brand_info_entry)
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return brand_info

result = []
current_year = datetime.now().year
# for year in years:
result.extend(get_brand_info(2024))
print("total:", len(result))

# for brand in brand_info:
#     print(json.dumps(brand, ensure_ascii=False, indent=4)) # json 형식으로 출력