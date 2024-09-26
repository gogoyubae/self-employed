import requests
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()
OPEN_DATA_API_KEY = os.environ.get('OPEN_DATA_API_KEY')

BRAND_FRC_BZMN_AVRGSLS="http://apis.data.go.kr/1130000/FftcBrandFrcsUnitAvrSalInfo2_Service/getbrandFrcsBzmnAvrgsls"

# 서울 지역 브랜드 매출 비용
def get_brand_frc_bzmn_avrgsls(brand_mnno):
    current_year = datetime.now().year
    for i in range(10):
        brand_frc_bzmn_avrgsls_params = {
            "serviceKey": OPEN_DATA_API_KEY,
            "pageNo": 1,
            "numOfRows": 1, # page의 첫 번째 데이터 -> 서울
            "resultType": 'json',
            "jngBizCrtraYr": current_year - i,
            "brandMnno": brand_mnno
        }

        try:
            response = requests.get(BRAND_FRC_BZMN_AVRGSLS, params=brand_frc_bzmn_avrgsls_params)
            data = response.json()

            if response.status_code != 200 or not ('items' in data and data['items']):
                continue

            items = data["items"]
            if items[0]['fyerAvrgSlsAmtScopeVal'] == 'null' or items[0]['fyerAvrgSlsAmtScopeVal'] == 0:
                continue
            return items[0]['fyerAvrgSlsAmtScopeVal']
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return None