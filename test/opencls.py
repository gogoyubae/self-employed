import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# .env 파일에서 환경 변수 로드
load_dotenv()

# 환경 변수로부터 API 키 가져오기
business_api_key = os.getenv('BUSINESS_API_KEY')
passenger_api_key = os.getenv('PASSENGER_API_KEY')
kakao_api_key = os.getenv('KAKAO_API_KEY')

# 서울시 상권 API 비동기 호출 함수
async def fetch_sangwon_data(session, api_key, start_index, end_index):
    url = f"http://openapi.seoul.go.kr:8088/{api_key}/xml/VwsmSignguStorW/{start_index}/{end_index}/"
    async with session.get(url) as response:
        if response.status == 200:
            return await response.text()
        else:
            print(f"Error: {response.status}")
            return None

# Kakao Map API 비동기 호출 함수
async def get_nearby_station(session, gu_name, kakao_api_key):
    query = f"{gu_name} 근처역"
    url = f"https://dapi.kakao.com/v2/local/search/keyword.json?query={query}"
    headers = {"Authorization": f"KakaoAK {kakao_api_key}"}
    
    async with session.get(url, headers=headers) as response:
        if response.status == 200:
            data = await response.json()
            stations = []
            for place in data['documents']:
                station_name = place['place_name'].split()[0].replace("역", "")  # "강남역"을 "강남"으로 변환
                if station_name not in stations:  # 중복된 역 이름은 제외
                    stations.append(station_name)
                if len(stations) >= 3:  # 상위 3개 역만
                    break
            return stations
        else:
            print(f"Error: {response.status}")
            return []

# 서울시 승차 인원 API 비동기 호출 함수
async def fetch_passenger_data(session, api_key, station_name, use_ymd):
    # 날짜와 함께 승차 인원 API 호출
    url = f"http://openapi.seoul.go.kr:8088/{api_key}/xml/CardSubwayStatsNew/1/1000/{use_ymd}"
    async with session.get(url) as response:
        if response.status == 200:
            # XML 데이터를 파싱
            xml_data = await response.text()
            root = ET.fromstring(xml_data)
            total_boarding = 0
            total_alighting = 0
            
            # row 태그에서 역명을 찾고 승차, 하차 인원 합산
            for row in root.findall(".//row"):
                station = row.find('SBWY_STNS_NM').text
                if station_name in station:  # 역 이름만 비교하고 호선 정보는 무시
                    boarding = int(row.find('GTON_TNOPE').text)  # 승차총승객수
                    alighting = int(row.find('GTOFF_TNOPE').text)  # 하차총승객수
                    total_boarding += boarding
                    total_alighting += alighting
            
            # 총 승차 + 하차 인원 반환
            return total_boarding + total_alighting
        else:
            print(f"Error: {response.status}")
            return 0

# 날짜 -2일 설정 함수
def get_date_minus_days(days):
    target_date = datetime.now() - timedelta(days=days)
    return target_date.strftime("%Y%m%d")

# 비동기적으로 서울시 상권 데이터, 카카오 API, 승차 인원 API를 모두 호출하는 함수
async def fetch_all_data(page_size):
    async with aiohttp.ClientSession() as session:
        # Kakao Map API 비동기 호출
        stations_task = get_nearby_station(session, "강남구", kakao_api_key)
        stations = await stations_task
        print(f"주변역: {stations}")

        # 서울시 상권 데이터 비동기 호출 (비동기로 처리 가능)
        sangwon_data_task = fetch_sangwon_data(session, business_api_key, 1, page_size)
        sangwon_data = await sangwon_data_task  # 상권 데이터 가져오기
        print(f"1부터 {page_size}까지 데이터 요청 중...")

        # 서울시 승차 인원 데이터를 가져오기 위한 날짜 설정 (현재 날짜 -2일)
        use_ymd = get_date_minus_days(14)

        # 역별로 승차 인원 수 확인
        passenger_tasks = [fetch_passenger_data(session, passenger_api_key, station, use_ymd) for station in stations]
        passenger_results = await asyncio.gather(*passenger_tasks)

        # 결과 출력
        for station, total_passengers in zip(stations, passenger_results):
            print(f"{station}: {total_passengers}명, 날짜 {use_ymd}")

        # XML 파싱 및 출력
        root = ET.fromstring(sangwon_data)
        for row in root.findall(".//row"):
            gu_name = row.find('SIGNGU_CD_NM').text
            industry_name = row.find('SVC_INDUTY_CD_NM').text
            year_quarter_code = row.find('STDR_YYQU_CD').text

            # 강남구, 편의점, 기준 년분기 코드 "20242" 필터링
            if gu_name == "강남구" and industry_name == "편의점" and year_quarter_code == "20242":
                data = {
                    "기준_년분기_코드": year_quarter_code,
                    "자치구_코드": row.find('SIGNGU_CD').text,
                    "자치구_코드_명": gu_name,
                    "서비스_업종_코드": row.find('SVC_INDUTY_CD').text,
                    "서비스_업종_코드_명": industry_name,
                    "점포_수": row.find('STOR_CO').text,
                    "유사_업종_점포_수": row.find('SIMILR_INDUTY_STOR_CO').text,
                    "개업_율": row.find('OPBIZ_RT').text,
                    "개업_점포_수": row.find('OPBIZ_STOR_CO').text,
                    "폐업_률": row.find('CLSBIZ_RT').text,
                    "폐업_점포_수": row.find('CLSBIZ_STOR_CO').text,
                    "프랜차이즈_점포_수": row.find('FRC_STOR_CO').text,
                }
                print(data)
                return  # "20242" 데이터를 찾으면 함수 종료

# 실행 코드
if __name__ == "__main__":
    page_size = 500  # 한 번에 가져올 데이터 수 (500개씩 요청)

    # 비동기 실행
    asyncio.run(fetch_all_data(page_size))
