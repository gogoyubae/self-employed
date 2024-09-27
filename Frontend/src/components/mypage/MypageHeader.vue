<template>
  <div>
    <img
      src="@/assets/img/headers/mypageheader.jpg"
      class="result-image mb-10"
    />
    <div class="container">
      <div class="result-text">마이페이지</div>
    </div>
  </div>
</template>

<script setup></script>

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
  top: 30%; /* 컨테이너의 중간 */
  left: 15%; /* 컨테이너의 중간 */
  transform: translate(-50%, -50%); /* 중앙 정렬 */
  color: white; /* 텍스트 색상 */
  padding: 10px; /* 여백 추가 */
  border-radius: 5px; /* 모서리 둥글게 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */
  font-size: 30px;
}

.result-text2 {
  color: rgb(0, 0, 0); /* 텍스트 색상 */
  padding: 10px; /* 여백 추가 */
  font-size: 50px;
  flex-grow: 1; /* 오른쪽 영역이 늘어나도록 설정 */
  margin-left: 10px; /* 텍스트 간격 */
}

.overlay {
  position: absolute; /* 절대 위치 설정 */
  top: 35%; /* user-info의 하단에 위치 */
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
  width: 100%;

  font-size: 24px; /* 텍스트 크기 조정 */
  margin: 2% 0; /* 위아래에 10%의 여백 추가 */
}

.container {
  padding: 0px 80px 0px 80px;
}

.flex-item {
  flex: 1;
  text-align: center;
}
</style>
