<template>
  <div>
    <CommunityHeader />
    <div class="container"> 
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
        <RouterLink to="/community" class="btn btn-sm btn-neutral mb-5 mt-1">목록</RouterLink>            
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
import CommunityHeader from '@/components/community/CommunityHeader.vue';

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

</style>