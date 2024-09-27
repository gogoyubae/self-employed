<template>
  <div class="container">
    <!-- 작성 버튼 추가 -->
    <div v-if="showCreateButton" class="d-flex justify-content-end mb-3">
      <a href="community/create">
        <button type="button" class="btn btn-sm btn-neutral">
          글쓰기
        </button>
      </a>
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

      <!-- 페이지네이션 기능 -->
      <div v-if="showPagination" class="py-4 px-6 d-flex justify-content-center">
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
              <a class="page-link me-3" href="#">
                <i class="bi bi-chevron-right"></i>
              </a>
            </li>
          </ul>
        </nav>
      </div>

      <!-- 검색 기능 -->
      <div v-if="showSearch" class="row justify-content-center mb-10">
        <div class="col-5">
          <div class="mt-2">
            <form class="form-group">
              <div class="input-group input-group-sm">
                <div class="btn-group dropdown">
                  <select class="form-select" aria-label="Default select example">
                    <option selected>전체</option>
                    <option value="1">작성자</option>
                    <option value="2">제목</option>
                    <option value="3">내용</option>
                  </select>
                </div>
                <input
                  type="text"
                  class="rounded form-control ms-1"
                  placeholder="검색어를 입력해 주세요."
                />
                <span class="ms-1 rounded input-group-text">
                  <i class="bi bi-search"></i>
                </span>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, defineProps } from 'vue';

const props = defineProps({
  showPagination: {
    type: Boolean,
    default: true
  },
  showSearch: {
    type: Boolean,
    default: true
  },
  showCreateButton: {
    type: Boolean,
    default: true // 기본값은 true로 설정, 필요시 변경 가능
  }
});

const posts = ref([
  {
    id: 3,
    title: '제목공간제목공간',
    author: '누구1',
    views: 1234,
    likes: 3,
    date: '2024-07-28',
  },
  {
    id: 2,
    title: '제목공간제목공간',
    author: '누구2',
    views: 1234,
    likes: 2,
    date: '2024-07-29',
  },
  {
    id: 1,
    title: '제목공간제목공간제목',
    author: '누구3',
    views: 1234,
    likes: 5,
    date: '2024-08-29',
  },
]);
</script>

<style scoped></style>
