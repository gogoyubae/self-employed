<template>
  <div>
    <img src="@/assets/img/community/talking.png" class="result-image mb-10">
    <div class="container">
      <div class="result-text">커뮤니티</div>
      <div class="overlay">
        <div class="overlay-text">
          <div class="text-center d-flex justify-content-center">
            <div class="d-flex w-100" style="max-width: 1000px;">
              <div class="flex-item" v-for="category in categories" :key="category.name">
                <a :href="category.link"><h4>{{ category.name }}</h4></a>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="d-flex align-items-end justify-content-between">
        <div>
          <h3 class="fw-semibold mb-5">{{ post.title }}</h3>
          <p class="text-m text-muted mb-5">
            {{ post.content }}
          </p>
        </div>
      </div>
      <div class="text-center gap-2 mb-5">
        <button type="button" class="btn btn-sm btn-neutral mx-1">👍 추천</button>
        <button type="button" class="btn btn-sm btn-neutral mx-1">👎 비추천</button>
      </div>

      <div class="text-center gap-2">
        <button type="button" class="btn btn-sm btn-neutral mb-5 mt-1">목록</button>
      </div>

      <div class="list-group mt-5 mb-5">
        <h4 class="fw-semibold mb-5">댓글 {{ comments.length }}</h4>
        <div class="list-group-item py-3" v-for="comment in comments" :key="comment.author">
          <div class="d-flex flex-wrap w-100 justify-content-between py-2">
            <h6>{{ comment.author }}</h6>
          </div>
          <p class="fs-sm font-weight-normal text-body py-2">{{ comment.content }}</p>
          <small class="text-muted">{{ comment.date }}</small>
        </div>
      </div>

      <nav aria-label="Page navigation example">
        <ul class="pagination justify-content-center pagination-spaced gap-1">
          <li class="page-item">
            <a class="page-link" href="#">
              <i class="bi bi-chevron-left"></i>
            </a>
          </li>
          <li class="page-item" v-for="page in totalPages" :key="page">
            <a class="page-link" href="#">{{ page }}</a>
          </li>
          <li class="page-item">
            <a class="page-link" href="#">
              <i class="bi bi-chevron-right"></i>
            </a>
          </li>
        </ul>
      </nav>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';

// 카테고리
const categories = ref([
  { name: '음식/음료', link: '#' },
  { name: '유통', link: '#' },
  { name: '패션/뷰티', link: '#' },
  { name: '의료', link: '#' },
  { name: '여가/오락', link: '#' },
]);

const post = ref({
  title: '제목제목제목제목제목',
  content: `내용내용내용내용내용내용
            내용내용
            내용내용내용내용
            내용내용내용내용내용내용내용내용내용내용
            내용내용내용내용내용내용내용내용내용내용
            내용내용내용내용내용내용내용내용내용내용`
});

const comments = ref([
  { author: '작성자1', content: '댓글댓글댓글댓글댓글...', date: '2014-01-23' },
  { author: '작성자2', content: '댓글댓글댓글댓글...', date: '2015-01-25' },
  { author: '작성자3', content: '댓글댓글댓글댓글...', date: '2017-03-23' },
]);

const totalPages = ref(5); // 페이지네이션
</script>
<style scoped>
.result-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
}

.result-image {
  width: 100%; /* 이미지가 컨테이너 너비에 맞게 조정 */
  height: 300px; /* 비율 유지 */
  object-fit: cover;
  z-index: 1; /* 이미지가 아래에 위치하도록 설정 */
  opacity: 0.5;

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

.result-text2-container {
  position: absolute; /* 절대 위치 설정 */
  top: 23%; /* 컨테이너의 중간 */
  left: 9.3%; /* 고정 위치 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */

  display: flex; /* 플렉스 박스 사용 */
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

.table-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
  z-index: 3; /* 테이블이 overlay 위에 위치하도록 설정 */
  margin-top: 20px; /* 테이블이 overlay와 겹치지 않도록 여백 추가 */
}

.container {
  padding: 0px 80px 0px 80px;
}

.flex-item {
  flex: 1;
  text-align: center;
}
</style>