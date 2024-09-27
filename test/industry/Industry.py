from dotenv import load_dotenv
import os
from datetime import datetime
from brand_startup_cost import get_brand_fntn_stats
from brand_info import get_brand_info

def main():
    load_dotenv()
    # DB 정보
    connection = pymysql.connect(
        host=os.environ.get('HOST'),
        user=os.environ.get('USER'),
        password=os.environ.get('PASSWORD'), 
        charset='utf8'
    )
    cursor = connection.cursor()

brand_fntn_info = {} # 창업 비용 정보
for year in range(datetime.now().year - 1, 2017, -1):
    get_brand_fntn_stats(brand_fntn_info, year)

print("브랜드 창업 비용 정보 총 개수:", len(brand_fntn_info))

result = []
year = 2023
result.extend(get_brand_info(brand_fntn_info, year))