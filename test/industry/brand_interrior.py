import requests
from dotenv import load_dotenv

import os

load_dotenv()
API_KEY = os.environ.get('API_KEY')

BRAND_FRCS_BZM_INTRRCTINFO_URL = "http://apis.data.go.kr/1130000/FftcBrandFrcsIntInfo2_Service/getbrandFrcsBzmnIntrrctinfo"

# 인테리어 비용
def find_interior_cost(brand_info, year):
    brand_frcs_bzm_intrrctinfo_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "jngBizCrtraYr": year,
        "brandMnno": brand_info['brand_mnno']
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