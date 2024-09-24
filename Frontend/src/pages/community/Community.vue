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
          <div class="border-top">
              <div class="table-responsive">
                <table class="table table-nowrap text-center">
                  <thead>
                    <tr>
                      <th scope="col">번호</th>
                      <th scope="col">제목</th>
                      <th scope="col">작성자</th>
                      <th scope="col">조회</th>
                      <th scope="col">추천</th>
                      <th scope="col">작성일</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="post in posts" :key="post.id">
                      <td>{{ post.id }}</td>
                      <td>
                        <a :href="'community/view/' + post.id">{{ post.title }}</a>
                      </td>
                      <td>{{ post.author }}</td>
                      <td>{{ post.views }}</td>
                      <td>{{ post.likes }}</td>
                      <td>{{ post.date }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="py-4 px-6">
                <div class="row align-items-center justify-content-between">
                  <div class="col-md-6 d-none d-md-block">
                  </div>
                  <div class="col-md-auto">
                    <nav aria-label="Page navigation example">
                      <ul class="pagination pagination-spaced gap-1">
                        <li class="page-item">
                          <a class="page-link" href="#">
                            <i class="bi bi-chevron-left"></i>
                          </a>
                        </li>
                        <li class="page-item"><a class="page-link" href="#">1</a></li>
                        <li class="page-item"><a class="page-link" href="#">2</a></li>
                        <li class="page-item"><a class="page-link" href="#">3</a></li>
                        <li class="page-item"><a class="page-link" href="#">4</a></li>
                        <li class="page-item"><a class="page-link" href="#">5</a></li>
                        <li class="page-item">
                          <a class="page-link" href="#">
                            <i class="bi bi-chevron-right"></i>
                          </a>
                        </li>
                        <a href="community/create"><button type="button" class="btn btn-sm btn-neutral">작성</button></a>
                      </ul>
                    </nav>
                  </div>
                </div>
              </div>
          </div>
        </div>
    </div>
</template>

<script setup>
import { ref } from 'vue';

const posts = ref([
  { id: 3, title: '제목공간제목공간', author: '누구1', views: 1234, likes: 3, date: '2024-07-28' },
  { id: 2, title: '제목공간제목공간', author: '누구2', views: 1234, likes: 2, date: '2024-07-29' },
  { id: 1, title: '제목공간제목공간제목', author: '누구3', views: 1234, likes: 5, date: '2024-08-29' },
]);

// 카테고리
const categories = ref([
  { name: '음식/음료', link: '#' },
  { name: '유통', link: '#' },
  { name: '패션/뷰티', link: '#' },
  { name: '의료', link: '#' },
  { name: '여가/오락', link: '#' },
]);
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