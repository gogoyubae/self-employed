<template>
  <div>
    <CommunityHeader />
    <div class="container">
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
import CommunityHeader from '@/components/community/CommunityHeader.vue';

// Reactive properties for title and content
const postTitle = ref('');
const postContent = ref('');
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
</style>
