import requests
import json
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

BRAND_FRCS_BZM_INTRRCTINFO_URL = "http://apis.data.go.kr/1130000/FftcBrandFrcsIntInfo2_Service/getbrandFrcsBzmnIntrrctinfo"
BRAND_FRC_BZMN_AVRGSLS="http://apis.data.go.kr/1130000/FftcBrandFrcsUnitAvrSalInfo2_Service/getbrandFrcsBzmnAvrgsls"
FFTC_BRAND_FNTN_STATS_URL = "http://apis.data.go.kr/1130000/FftcBrandFntnStatsService/getBrandFntnStats"
BRAND_INFO_URL = "http://apis.data.go.kr/1130000/FftcBrandRlsInfo2_Service/getBrandinfo"

API_KEY = os.environ.get('API_KEY')


# 인테리어 비용
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


# 서울 지역 브랜드 매출 비용
def get_brand_frc_bzmn_avrgsls(year, brand_mnno):
    brand_frc_bzmn_avrgsls_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": 'json',
        "jngBizCrtraYr": year,
        "brandMnno": brand_mnno
    }

    try:
        response = requests.get(BRAND_FRC_BZMN_AVRGSLS, params=brand_frc_bzmn_avrgsls_params)
        data = response.json()

        if response.status_code != 200 or not ('items' in data and data['items']):
            return 0

        items = data["items"]
        return items[0]['fyerAvrgSlsAmtScopeVal']
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")


# 브랜드별 창업 비용
def get_brand_fntn_stats(year):
    brand_fntn_stats_params = {
        "serviceKey": API_KEY,
        "pageNo": 1,
        "numOfRows": 1,
        "resultType": "json",
        "yr": year
    }

    response = requests.get(FFTC_BRAND_FNTN_STATS_URL, params=brand_fntn_stats_params)
    total_count = response.json()["totalCount"]
    print(total_count)
    
    for i in range(1, int(total_count / 100 + 2)): # 100개씩 저장
        brand_fntn_stats_params = {
            "serviceKey": API_KEY,
            "pageNo": i,
            "numOfRows": 100,
            "resultType": "json",
            "yr": year
        }

        try:
            response = requests.get(FFTC_BRAND_FNTN_STATS_URL, params=brand_fntn_stats_params)
            data = response.json()
            items = data["items"]
            
            brand_fntn_info = []

            for item in items:
                brand_fntn_info.append({
                    "induty_lclas_nm": item['indutyLclasNm'],            # 업종 대분류 이름 (외식)
                    "induty_mlsfc_nm": item['indutyMlsfcNm'],            # 업종 중분류 이름 (한식)
                    "brand_nm": item['brandNm'],                         # 브랜드 이름 (두돈까스)
                    "corp_nm": item['corpNm'],                           # 회사 이름 ((주)아이언가이즈)
                    "jng_bzmn_jng_amt": item['jngBzmnJngAmt'],           # 가맹 사업자 가맹 금액 (3300)
                    "jng_bzmn_edu_amt": item['jngBzmnEduAmt'],           # 가맹 사업자 교육비 (2200)
                    "jng_bzmn_assrnc_amt": item['jngBzmnAssrncAmt'],     # 가맹 사업자 보증금 (1000)
                    "jng_bzmn_etc_amt": item['jngBzmnEtcAmt'],           # 가맹 사업자 기타 금액 (29133)
                    "smtn_amt": item['smtnAmt']                          # 합계 금액 (35633)
                })
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return brand_fntn_info


# 브랜드 정보
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
                    "majr_gds_nm": majrGdsNm,                  # 주요 상품명
                    "fyer_avrg_sls_amt_scope_val": get_brand_frc_bzmn_avrgsls(year, brandMnno) # 연평균 매출 범위
                }

                get_interior_cost(brand_info_entry, brandMnno, year)
                brand_info.append(brand_info_entry)
                print(json.dumps(brand_info_entry, ensure_ascii=False, indent=4)) # json 형식으로 출력
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return brand_info

get_brand_fntn_stats(2023)

result = []
current_year = datetime.now().year
year = 2023
# for year in years:
result.extend(get_brand_info(2023))
print("total:", len(result))

# for brand in result:
#     print(json.dumps(brand, ensure_ascii=False, indent=4)) # json 형식으로 출력