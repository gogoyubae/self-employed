<template>
  <div class="result-container">
    <img src="@/assets/img/report/clothes.png" class="result-image mb-10" />
    <div class="container">
      <div class="result-text">분석 결과</div>
      <div class="result-text2-container">
        <div class="result-text2">패션 · 뷰티</div>
      </div>
      <div class="overlay">
        <div class="overlay-text">
          <!-- ||안의 text는 db에서 가져오는 거임 -->
          <div class="d-flex">
            <div class="question">자금</div>
            <div class="answer">3~5억</div>
            <div class="question">지역</div>
            <div class="answer">서울 강남구</div>
            <div class="question">대분류</div>
            <div class="answer">유통</div>
            <div class="question">중분류</div>
            <div class="answer">편의점</div>
            <div class="question">프랜차이즈</div>
          </div>
          <div class="d-flex">
            <div class="question">월세</div>
            <div class="answer">1000만원 이하</div>
            <div class="question">보증금</div>
            <div class="answer">1000만원 이하</div>
            <div class="question">거주지 인근</div>
            <div class="answer">30km 교육</div>
            <div class="question">대출 계획</div>
            <div class="answer">있음</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.result-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
}

.result-image {
  width: 100%; /* 이미지가 컨테이너 너비에 맞게 조정 */
  height: 300px; /* 비율 유지 */
  object-fit: cover;
  z-index: 1; /* 이미지가 아래에 위치하도록 설정 */
}

.result-text {
  position: absolute; /* 절대 위치 설정 */
  top: 25%; /* 컨테이너의 중간 */
  left: 14.2%; /* 컨테이너의 중간 */
  transform: translate(-50%, -50%); /* 중앙 정렬 */
  color: white; /* 텍스트 색상 */
  padding: 10px; /* 여백 추가 */
  border-radius: 5px; /* 모서리 둥글게 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */
  font-size: 30px;
}

.result-text2-container {
  position: absolute; /* 절대 위치 설정 */
  top: 25%; /* 컨테이너의 중간 */
  left: 9.3%; /* 고정 위치 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */
  display: flex; /* 플렉스 박스 사용 */
}

.result-text2 {
  color: white; /* 텍스트 색상 */
  padding: 10px; /* 여백 추가 */
  font-size: 50px;
  flex-grow: 1; /* 오른쪽 영역이 늘어나도록 설정 */
  margin-left: 10px; /* 텍스트 간격 */
}

.overlay {
  position: absolute; /* 절대 위치 설정 */
  top: 50%; /* user-info의 하단에 위치 */
  left: 50%; /* 가운데 정렬을 위해 left를 50%로 설정 */
  transform: translateX(-50%); /* 가운데 정렬 조정 */
  width: 80%; /* 너비를 60%로 설정하여 양쪽 20% 여백을 만듭니다 */
  background-color: rgba(255, 255, 255); /* 흰색 반투명 배경 */
  border-radius: 40px; /* 모서리 둥글게 */
  z-index: 1; /* 이미지 아래에 위치하도록 설정 */
  box-sizing: border-box; /* 패딩을 포함하여 전체 너비를 계산 */
}
.overlay-text {
  color: black; /* 텍스트 색상 */

  font-size: 24px; /* 텍스트 크기 조정 */
  margin: 2% 3%; /* 위아래에 10%의 여백 추가 */
}

.table-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
  z-index: 3; /* 테이블이 overlay 위에 위치하도록 설정 */
  margin-top: 20px; /* 테이블이 overlay와 겹치지 않도록 여백 추가 */
}

.container {
  padding: 0px 80px 0px 80px;
}
.question {
  color: black; /* 텍스트 색상 */
  font-size: 20px; /* 텍스트 크기 조정 */
  font-weight: 600;
  margin-right: 0.5rem;
}
.answer {
  color: black; /* 텍스트 색상 */
  font-size: 20px; /* 텍스트 크기 조정 */
  font-weight: 100;
  margin-right: 1rem;
}
</style>
