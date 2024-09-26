import requests
import pandas as pd
import time

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
def get_real_estate_list(ldongCd):
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
        # "selectPeriod": "PR"
    }

    # GET 요청 보내기
    response = requests.get(base_url, params=params)

    # 응답 확인 및 필요한 데이터 추출
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'resultList' in data['data']:
            extract_columns(data['data']['resultList'])
        else:
            print("No valid data found.")
    else:
        print(f"Error: {response.status_code}")

# 컬럼 추출 함수
def extract_columns(result_list):
    extracted_data = []

    for item in result_list:
        # 전체 컬럼
        sido_nm = item.get('sidoNm')  # 시/도 (서울특별시)
        sgg_nm = item.get('sggNm')    # 구 (서초구)
        emd_nm = item.get('emdNm')    # 동 (반포동)
        la_crd = item.get('laCrd')    # 위도 (37.4949233)
        lo_crd = item.get('loCrd')    # 경도 (127.0000303)
        atcl_no = item.get('atclNo')  # 매물 번호 - detail_page 필요 (315343221)
        ctgry_cd1 = item.get('ctgryCd1')  # 주요 카테고리 코드 - detail_page 필요 (SHP)
        ctgry_cd2_nm = item.get('ctgryCd2Nm')  # 세부 카테고리 이름 (일반상가)
        bzno = item.get('bzno')  # 사업자 등록번호 (220-23-00073)
        mdiat_bzest_nm = item.get('mdiatBzestNm')  # 중개업체명 (리더스공인중개사사무소)
        deal_kind_cd_nm = item.get('dealKindCdNm')  # 거래 유형 이름 (매매)
        bsc_tnth_wunt_amt = item.get('bscTnthWuntAmt')  # 기본 월세 금액 (90000(만원))
        add_tnth_wunt_amt = item.get('addTnthWuntAmt')  # 추가 월세 금액 (0)
        atcl_sfe_cn = item.get('atclSfeCn')  # 매물 설명 (서래마을 귀한 1층 상가 매매..)
        atcl_reg_dttm = item.get('atclRegDttm')  # 매물 등록일시 (2024-09-12 11:13:23)
        area1 = item.get('area1')  # 면적 (㎡) (64.51)
        area2 = item.get('area2')  # 면적 (㎡) (55.02)
        photo_list = item.get('photoList', [])
        image_data = photo_list[0].get('imageData') if photo_list else None # 썸네일 (https://newimg.serve.co.kr/article_photo/2024/09/12/14991786/20240912111323289.png)

        extracted_data.append({
            'sido_nm': sido_nm,  # 시/도 (서울특별시)
            'sgg_nm': sgg_nm,    # 구 (서초구)
            'emd_nm': emd_nm,    # 동 (방배동)
            'la_crd': la_crd,    # 위도 (37.4863705)
            'lo_crd': lo_crd,    # 경도 (126.9939121)
            'atcl_no': atcl_no,  # 매물 번호 - detail_page 필요 (315382860)
            'ctgry_cd1': ctgry_cd1,  # 주요 카테고리 코드 - detail_page 필요 (SHP)
            'ctgry_cd2_nm': ctgry_cd2_nm,  # 세부 카테고리 이름 (일반상가)
            'bzno': bzno,  # 사업자 등록번호 (482-07-02306)
            'mdiat_bzest_nm': mdiat_bzest_nm,  # 중개업체명 (이수자이멘토부동산공인중개사사무소)
            'deal_kind_cd_nm': deal_kind_cd_nm,  # 거래 유형 이름 (월세)
            'bsc_tnth_wunt_amt': bsc_tnth_wunt_amt,  # 기본 월세 금액 (4000)
            'add_tnth_wunt_amt': add_tnth_wunt_amt,  # 추가 월세 금액 (200)
            'atcl_sfe_cn': atcl_sfe_cn,  # 매물 설명 (렌트프리 적극협의 신축 2년차 상가, 사무실)
            'atcl_reg_dttm': atcl_reg_dttm,  # 매물 등록일시 (2024-09-13 12:36:57)
            'area1': area1,  # 면적 (㎡) (113.93)
            'area2': area2,  # 면적 (㎡) (113.93)
            'image_data': image_data  # 썸네일
        })

    # 추출된 데이터 출력
    # for row in extracted_data:
    #     print(row)

    print("결과: ", len(result_list))

# 거래 종류 선택
selected_deal_types = ["월세", "매매"]

pageNum = 0
offset = 10000

# 매물 정보 가져오기
# get_real_estate_list(selected_deal_types)

file_name = 'test\서울시_법정동코드.xls'

df = pd.read_excel(file_name)

dong_code_list = []

# 데이터 프레임 출력
for dong_code in df.values:
    dong_code_list.append([dong_code[0],dong_code[1]])

start_time = time.time() # 크롤링 시작
for dong_code in dong_code_list:
    print(dong_code[1], end=" ")
    get_real_estate_list(dong_code[0])
end_time = time.time()
print('total_time')
print(end_time - start_time) # 73 s