import requests
from haversine import haversine

# 기본 URL
base_url = "https://www.serve.co.kr/good/v1/map/getAtclList"


# 거래 종류에 따른 코드 매핑
deal_types = {
    "매매": "A1",
    "전세": "B1",
    "월세": "B2",
    "단기임대": "B3"
}


# 선택한 거래 종류에 맞는 코드를 생성하는 함수
def get_deal_kind_codes(selected_deal_types):
    return ",".join([deal_types[deal] for deal in selected_deal_types])


# 매물 정보를 가져오는 함수
def find_property_info_by_dong(ldongCd):
    deal_kind_cd_list_str = get_deal_kind_codes(selected_deal_types)
    
    params = {
        "tabNo": 4,
        "sno": "",
        "ldongCd": ldongCd,  # 서울 서초구 반포동 예시
        "aptNo": "",
        "laCrd": "",
        "loCrd": "",
        "maxLaCrd": "",
        "maxLoCrd": "",
        "minLaCrd": "",
        "minLoCrd": "",
        "orderCd": 1,
        "ctgryCdList": "SHP01,SHP02,SHP03,OFC01,OFC02,OFC03,OFC05",
        "zoneNo": "",
        "dealKindCdListStr": deal_kind_cd_list_str,  # 거래 종류 코드
        "maxBscTnthWuntAmt": "",
        "maxAddTnthWuntAmt": "",
        "pageNum": pageNum,  # 페이지 번호
        "offset": offset,  # 데이터 오프셋
    }

    # GET 요청 보내기
    response = requests.get(base_url, params=params)

    # 응답 확인 및 필요한 데이터 추출
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'resultList' in data['data']:
            return data['data']['resultList']
        else:
            print("No valid data found.")
    else:
        print(f"Error: {response.status_code}")


# 컬럼 추출 함수
def find_property_within_radius(result_list, current_location, radius):
    property_list = []

    for item in result_list:
        compare = (item.get('laCrd'), item.get('loCrd'))
        if haversine(current_location, compare, unit = 'm') > radius: # 미터 단위
            continue

        photo_list = item.get('photoList', [])
        image_data = photo_list[0].get('imageData') if photo_list else None # 썸네일 (https://newimg.serve.co.kr/article_photo/2024/09/12/14991786/20240912111323289.png)
        
        property_list.append({
            'atcl_sfe_cn': item.get('atclSfeCn'),                      # 매물 설명 == 건물 이름(?) (렌트프리 적극협의 신축 2년차 상가, 사무실)
            'mdiat_bzest_addr': item.get('mdiatBzestAddr'),            # 매물 상세 위치 (서울특별시 서초구 반포동 104-1)
            'bsc_tnth_wunt_amt': item.get('bscTnthWuntAmt'),           # 보증금 (1000 만)
            'add_tnth_wunt_amt': item.get('addTnthWuntAmt'),           # 월세금액 (50 만)
            'area1':  item.get('area1'),                               # 계약 면적 (㎡) (113.93)
            'area2':  item.get('area2'),                               # 전용 면적 (㎡) (113.93)
            'mdiat_bzest_nm': item.get('mdiatBzestNm'),                # 중개업체명 (이수자이멘토부동산공인중개사사무소)
            "mdiat_bzest_rep_telno": item.get('mdiatBzestRepTelno'),   # 대표 전화번호 (02-537-8040)
            "mdiat_bzest_rep_moblno": item.get('mdiatBzestRepMoblno'), # 대표 휴대폰 번호(010-8983-8100)
            'image_data': image_data,       # 썸네일
            'atcl_reg_dttm': item.get('atclRegDttm'),                  # 매물 등록일시 (2024-09-13 12:36:57)
            'la_crd': item.get('laCrd'),    # 위도 (37.4863705)
            'lo_crd': item.get('loCrd'),    # 경도 (126.9939121)
        })
    
    return property_list


# 거래 종류 선택
selected_deal_types = ["월세", "매매"]

pageNum = 0
offset = 10000

# 매물 정보 가져오기
property_by_dong = find_property_info_by_dong(1117013600)

property_by_radius =find_property_within_radius(property_by_dong, (37.52687181000000, 127.00093640000000), 600) # 서울 용구 보광동, 600m 내 매물
# print("[서울 용구 보광동 600m 내 매물 목록] ->", len(property_by_radius))
# print(property_by_radius)
# print()
# property_by_dong = find_property_info_by_dong(1168010500)
# property_by_radius =find_property_within_radius(property_by_dong, (37.51396894000000, 127.05612160000000), 600) # 서울 강남구 삼성동, 600m 내 매물
# print("[서울 강남구 삼성동 600m 내 매물 목록] ->", len(property_by_radius))
