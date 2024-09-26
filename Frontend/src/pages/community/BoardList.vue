<template>
<div class="container">
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
        <div class="col-md-6 d-none d-md-block"></div>
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
                <a href="community/create">
                <button type="button" class="btn btn-sm btn-neutral">작성</button>
                </a>
            </ul>
            </nav>
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
</script>

<style scoped>
</style>
