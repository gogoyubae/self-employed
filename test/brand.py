import mysql.connector
import openai
from dotenv import load_dotenv
import os

# .env 파일에서 환경 변수 로드
load_dotenv()

# OpenAI API 설정
openai.api_key = os.getenv('OPENAI_API_KEY')

# MySQL 데이터베이스 연결 설정
conn = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME')
)

cursor = conn.cursor()

# 업종 중분류 종류 13개 정의
categories = [
    "한식", "일식/중식/양식", "제과/커피/패스트푸드", 
    "기타요식", "편의점", "할인점/슈퍼마켓", 
    "의복/의류", "패션/잡화", "미용서비스", 
    "화장품", "유흥", "스포츠/문화/레저", "여행"
]

def get_industry_category(title):
    # 프롬프트에 categories 리스트를 명시하고, 반드시 그 중 하나를 선택하도록 요청
    prompt = f"Given the title '{title}', please choose the best fitting category from the following list: {', '.join(categories)}. Only respond with the category name in Korean."

    response = openai.ChatCompletion.create(
        model="gpt-4",  # 사용 중인 모델
        messages=[
            {"role": "system", "content": "You are an assistant that categorizes business titles into predefined categories."},
            {"role": "user", "content": prompt}
        ]
    )
    
    # 응답에서 카테고리 이름만 추출하여 반환
    content = response['choices'][0]['message']['content'].strip()
    
    # 응답이 categories 리스트에 있는지 확인 (혹시나 다른 응답이 나올 경우 대비)
    if content in categories:
        return content
    else:
        # 만약 응답이 리스트에 없다면 기본값으로 처리
        return "기타"  # 기본값으로 '기타'를 반환하거나 다른 적합한 카테고리 사용

# 'industry_subcategory'가 NULL인 데이터만 조회
cursor.execute("SELECT video_id, title FROM individual_edu WHERE industry_subcategory IS NULL")
rows = cursor.fetchall()

# 각 제목에 대해 업종 중분류 추출 및 DB 업데이트
for row in rows:
    video_id, title = row
    industry_category = get_industry_category(title)
    print(f"Updating record {video_id} with category: {industry_category}")
    cursor.execute('UPDATE individual_edu SET industry_subcategory = %s WHERE video_id = %s', (industry_category, video_id))

# 변경사항 저장 및 연결 종료
conn.commit()
cursor.close()
conn.close()
