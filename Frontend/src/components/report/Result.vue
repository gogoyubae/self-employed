<template>
  <div class="result-container">
    <img src="@/assets/img/report/clothes.png" class="result-image" />
    <div class="result-text">분석 결과</div>
    <div class="result-text2-container">
      <div class="result-text2">패션 · 뷰티</div>
    </div>
    <div class="overlay">
      <div class="overlay-text">
        <!-- ||안의 text는 db에서 가져오는 거임 -->
        자금 3~5억 | 지역 서울 강남구 | 대분류 유통 | 중분류 편의점 | 프랜차이즈
        <br />
        월세 1000만원 이하 | 보증금 1000만원 이하 | 거주지 인근 30km 교육
        <br />
        필요함| 대출 계획 있음
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
  height: auto; /* 비율 유지 */
  z-index: 1; /* 이미지가 아래에 위치하도록 설정 */
}

.result-text {
  position: absolute; /* 절대 위치 설정 */
  top: 25%; /* 컨테이너의 중간 */
  left: 15%; /* 컨테이너의 중간 */
  transform: translate(-50%, -50%); /* 중앙 정렬 */
  color: white; /* 텍스트 색상 */

  padding: 10px; /* 여백 추가 */
  border-radius: 5px; /* 모서리 둥글게 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */

  font-size: 25px;
}

.result-text2-container {
  position: absolute; /* 절대 위치 설정 */
  top: 23%; /* 컨테이너의 중간 */
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
  top: 45%; /* user-info의 하단에 위치 */
  left: 50%; /* 가운데 정렬을 위해 left를 50%로 설정 */
  transform: translateX(-50%); /* 가운데 정렬 조정 */
  width: 80%; /* 너비를 60%로 설정하여 양쪽 20% 여백을 만듭니다 */
  height: 45%; /* 높이를 자동으로 조정 */
  background-color: rgba(255, 255, 255, 0.7); /* 흰색 반투명 배경 */
  border-radius: 40px; /* 모서리 둥글게 */
  z-index: 1; /* 이미지 아래에 위치하도록 설정 */
  box-sizing: border-box; /* 패딩을 포함하여 전체 너비를 계산 */
}

.overlay-text {
  color: black; /* 텍스트 색상 */
  font-size: 28px; /* 텍스트 크기 조정 */
  margin: 2% 2%; /* 위아래에 10%의 여백 추가 */
}
</style>
