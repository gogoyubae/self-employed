import requests
from dotenv import load_dotenv
import os

load_dotenv()
KAKAO_REST_API_KEY = os.environ.get('KAKAO_REST_API_KEY')

KEYWORD_SEARCH_URL = "https://dapi.kakao.com/v2/local/search/keyword.json"

def count_brands_by_radius(lat, lng, brand_name, radius):
    page = 1

    params = {
        'radius': radius, # (단위: 미터(m), 최소: 0, 최대: 20000)
        'query': brand_name,
        'page': page
    }
    
    if lat is not None and lng is not None:
        params['y'] = lat  # 위도(Latitude)
        params['x'] = lng  # 경도(Longitude)

    # 요청 헤더 설정
    headers = {
        'Authorization': f'KakaoAK {KAKAO_REST_API_KEY}'
    }

    # GET 요청 보내기
    response = requests.get(KEYWORD_SEARCH_URL, headers=headers, params=params)

    # 응답 확인
    if response.status_code == 200:
        data = response.json()
        # place_names = [[item['place_name'], item['distance']] for item in data['documents']]
        return data['meta']['total_count']
    else:
        print(f"Error: {response.status_code} - {response.text}")

# print(count_brands_by_radius(37.547913 , 127.07461, "CU", 1000))
# print(count_brands_by_radius(0, 0, "광진구 능동 CU", 1000))