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
      <div class="flex-fill overflow-y-lg-auto scrollbar bg-body rounded-top-4 rounded-top-start-lg-4 rounded-top-end-lg-0 border-top border-lg shadow-2">
        <main class="container-fluid px-6 pb-10">
          <div class="row align-items-center g-3 mt-6">
            <div class="col-md-12 col-xl-12">
              <input 
                type="text" 
                class="form-control" 
                placeholder="제목을 입력하세요." 
                v-model="postTitle" 
              />
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3">
            <label class="visually-hidden">내용</label>
            <div class="col-md-12 col-xl-12">
              <Editor v-model="postContent" />
            </div>
          </div>
          <hr class="my-6" />
          <div class="d-flex justify-content-end gap-2">
            <button type="button" class="btn btn-sm btn-neutral" @click="resetFields">취소</button>
            <button type="button" class="btn btn-sm btn-primary" @click="submitPost">등록</button>
          </div>
        </main>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import Editor from '@/components/editor/Editor.vue';

// Reactive properties for title and content
const postTitle = ref('');
const postContent = ref('');
const categories = ref([
  { name: '음식/음료', link: '#' },
  { name: '유통', link: '#' },
  { name: '패션/뷰티', link: '#' },
  { name: '의료', link: '#' },
  { name: '여가/오락', link: '#' },
]);

// Method to handle post submission
const submitPost = () => {
  if (postTitle.value.trim() && postContent.value.trim()) {
    console.log('제목:', postTitle.value);
    console.log('내용:', postContent.value);
    // Here you can add functionality to send this data to a server if needed
    // For now, just reset the fields after submission
    resetFields();
  } else {
    alert('제목과 내용을 입력해주세요.');
  }
};

// Method to reset input fields
const resetFields = () => {
  postTitle.value = '';
  postContent.value = '';
};
</script>

<style scoped>
/* Your existing styles remain unchanged */
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

.container {
  padding: 0px 80px 0px 80px;
}

.flex-item {
  flex: 1;
  text-align: center;
}
</style>
